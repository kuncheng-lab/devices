// Package modbus_tcp 是 Modbus TCP 主站客户端：MBAP 报头组帧、收发、超时与异常应答。
//
// 与 modbus_rtu 的关系：功能码、地址、寄存器的语义完全一样，差别只在传输层 ——
// TCP 帧是「MBAP 报头(7 字节) + PDU」，**没有 CRC**；而 RTU 帧是「从站号 + PDU + CRC」。
// 很多人第一次用会把串口那串字节直接粘进 TCP 调试工具，从站一个字节都不回，就是少了报头。
//
//	MBAP:  事务号(2) 协议号(2)=0 长度(2) 单元号(1)   后接 功能码(1) 数据...
//
// 只覆盖桌面应用用得到的部分：读保持/输入寄存器（03H/04H）与写单个寄存器（06H）。
package modbus_tcp

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"
)

// 功能码。0x80 位在应答里表示异常。
const (
	FuncReadHolding byte = 0x03
	FuncReadInput   byte = 0x04
	FuncWriteSingle byte = 0x06
	fExceptionFlag  byte = 0x80

	mbapLen     = 7 // 事务号2 + 协议号2 + 长度2 + 单元号1
	maxPDU      = 260
	defaultPort = 502
)

// ErrTimeout 表示在等待时限内没有收齐一帧。
var ErrTimeout = errors.New("modbus_tcp: 等待应答超时")

// ExceptionError 是从站回的异常应答（功能码最高位置 1）。
//
// 异常码含义各厂家不一样，Error() 里的文字只是标准 Modbus 的说法；
// 排障时按设备手册的表对照（例如伟创 AC320 手册 11 = 读取参数字节数有误）。
type ExceptionError struct {
	Func byte
	Code byte
}

func (e *ExceptionError) Error() string {
	text := map[byte]string{
		0x01: "非法功能码",
		0x02: "非法数据地址",
		0x03: "非法数据值",
		0x04: "从站设备故障",
		0x05: "确认（从站已受理，需继续轮询）",
		0x06: "从站忙",
	}[e.Code]
	if text == "" {
		text = "标准 Modbus 未定义该码"
	}
	return fmt.Sprintf("modbus_tcp: 从站异常应答 功能码 0x%02X 异常码 0x%02X（%s）", e.Func, e.Code, text)
}

// Config 是连接参数。
type Config struct {
	// Host 是设备地址，写成 "192.168.3.30" 或 "192.168.3.30:502"；不带端口时用 502。
	Host string
	// UnitID 是 MBAP 里的单元号（对应串口的从站号）。很多设备忽略它，
	// 但协议要求填，填设备文档里那个值最保险。
	UnitID byte
	// ConnectTimeoutMS 为 0 时用 3 秒。
	ConnectTimeoutMS int
	// ResponseTimeoutMS 为 0 时用 2 秒；TCP 上不存在波特率受限，不需要按报文长度估。
	ResponseTimeoutMS int
	// Trace 非空时回调每次收发的十六进制原文，用于现场排障。
	Trace func(format string, args ...any)
}

func (cfg Config) addr() string {
	if cfg.Host == "" {
		return ""
	}
	if _, _, err := net.SplitHostPort(cfg.Host); err == nil {
		return cfg.Host
	}
	return fmt.Sprintf("%s:%d", cfg.Host, defaultPort)
}

func (cfg Config) connectTimeout() time.Duration {
	if cfg.ConnectTimeoutMS <= 0 {
		return 3 * time.Second
	}
	return time.Duration(cfg.ConnectTimeoutMS) * time.Millisecond
}

func (cfg Config) responseTimeout() time.Duration {
	if cfg.ResponseTimeoutMS <= 0 {
		return 2 * time.Second
	}
	return time.Duration(cfg.ResponseTimeoutMS) * time.Millisecond
}

// Client 是一台 Modbus TCP 从站的客户端。
//
// 与串口客户端不同，它**保持一条长连接**：TCP 上断开重连的代价比串口大得多，
// 而且没有"总线仲裁"问题 —— 一个连接就是一台设备，不必考虑别的从站。
// 出错时自动关掉连接，下一次调用重连。
type Client struct {
	mu   sync.Mutex
	cfg  Config
	conn net.Conn
	// txID 是事务号，每发一帧加一；应答的事务号必须与请求一致才认。
	txID uint16
}

// New 建立客户端，此时并不连接（首次收发时自动连）。
func New(cfg Config) *Client { return &Client{cfg: cfg} }

// SetConfig 换一套连接参数；会关掉现有连接，下次收发按新参数重连。
func (c *Client) SetConfig(cfg Config) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.closeLocked()
	c.cfg = cfg
}

// Host 返回当前配置的目标地址（配置页显示用）。
func (c *Client) Host() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.cfg.addr()
}

// IsOpen 报告当前有没有连上。
func (c *Client) IsOpen() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.conn != nil
}

// Close 关闭连接，可重复调用。
func (c *Client) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.closeLocked()
}

// ReadHoldingRegisters 读保持寄存器（0x03）。
func (c *Client) ReadHoldingRegisters(unit byte, addr, count uint16) ([]uint16, error) {
	return c.ReadRegisters(unit, FuncReadHolding, addr, count)
}

// ReadInputRegisters 读输入寄存器（0x04）。
func (c *Client) ReadInputRegisters(unit byte, addr, count uint16) ([]uint16, error) {
	return c.ReadRegisters(unit, FuncReadInput, addr, count)
}

// ReadRegisters 按功能码读寄存器。count 为 1~125（Modbus 对一帧的限制）。
//
// unit 为 0 时用配置里的 UnitID：现场常常不关心这个字段，让调用方可以省略。
func (c *Client) ReadRegisters(unit, fn byte, addr, count uint16) ([]uint16, error) {
	if fn != FuncReadHolding && fn != FuncReadInput {
		return nil, fmt.Errorf("modbus_tcp: 不支持的功能码 0x%02X", fn)
	}
	if count == 0 || count > 125 {
		return nil, fmt.Errorf("modbus_tcp: 一次读 %d 个寄存器超出 1~125 的范围", count)
	}

	pdu := []byte{fn, byte(addr >> 8), byte(addr), byte(count >> 8), byte(count)}
	resp, err := c.transact(unit, pdu, fn)
	if err != nil {
		return nil, err
	}
	// resp: 功能码 字节数 数据...（MBAP 已在 transact 里剥掉）
	if len(resp) < 2 {
		return nil, errors.New("modbus_tcp: 读应答过短")
	}
	n := int(resp[1]) / 2
	if len(resp) < 2+2*n {
		return nil, fmt.Errorf("modbus_tcp: 数据不完整（声明 %d 个寄存器，只收到 %d 字节）", n, len(resp)-2)
	}
	out := make([]uint16, n)
	for i := 0; i < n; i++ {
		out[i] = uint16(resp[2+2*i])<<8 | uint16(resp[3+2*i])
	}
	return out, nil
}

// WriteSingleRegister 写单个保持寄存器（0x06）。
func (c *Client) WriteSingleRegister(unit byte, addr, value uint16) error {
	pdu := []byte{FuncWriteSingle, byte(addr >> 8), byte(addr), byte(value >> 8), byte(value)}
	_, err := c.transact(unit, pdu, FuncWriteSingle)
	return err
}

// transact 是唯一的收发出入口：组装 MBAP、发一帧、收一帧、校验。
// 全程持锁，保证同一个连接上不会有两帧交叉（事务号也不会串）。
func (c *Client) transact(unit byte, pdu []byte, fn byte) ([]byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.cfg.Host == "" {
		return nil, errors.New("modbus_tcp: 未配置主机地址")
	}
	if unit == 0 {
		unit = c.cfg.UnitID
	}
	if err := c.ensureConnLocked(); err != nil {
		return nil, err
	}

	// 每次交易按当下时间重设收发时限：deadline 是绝对时刻，绝不能在建立连接时设一次
	// （那会让空闲之后的第一次请求立刻超时，见 ensureConnLocked 的注释）。
	if err := c.conn.SetDeadline(time.Now().Add(c.cfg.responseTimeout())); err != nil {
		c.closeLocked()
		return nil, fmt.Errorf("modbus_tcp: 设置收发时限失败 %w", err)
	}

	c.txID++
	txID := c.txID
	frame := make([]byte, 0, mbapLen+len(pdu))
	frame = append(frame,
		byte(txID>>8), byte(txID), // 事务号
		0x00, 0x00, // 协议号，固定 0
		byte((1+len(pdu))>>8), byte(1+len(pdu)), // 长度 = 单元号 + PDU
		unit)
	frame = append(frame, pdu...)
	c.trace("TX %s", hex.EncodeToString(frame))

	if _, err := c.conn.Write(frame); err != nil {
		c.closeLocked() // 连接坏了：关掉，下一次重连
		return nil, fmt.Errorf("modbus_tcp: 发送失败 %w", err)
	}

	resp, err := c.readFrameLocked(txID)
	if err != nil {
		// 超时或半帧都说明这条连接的状态不可信，关掉重来
		c.closeLocked()
		return nil, err
	}
	c.trace("RX %s", hex.EncodeToString(resp))

	// resp 已经去掉 MBAP，这里是 PDU：功能码 ...
	if len(resp) < 1 {
		return nil, errors.New("modbus_tcp: 空应答")
	}
	if resp[0] == fn|fExceptionFlag {
		if len(resp) < 2 {
			return nil, errors.New("modbus_tcp: 异常应答过短")
		}
		return nil, &ExceptionError{Func: fn, Code: resp[1]}
	}
	if resp[0] != fn {
		return nil, fmt.Errorf("modbus_tcp: 应答功能码不符 期望 0x%02X 收到 0x%02X", fn, resp[0])
	}
	return resp, nil
}

// readFrameLocked 读一整帧并剥掉 MBAP：
// 校验协议号为 0、事务号与请求一致，再按 MBAP 里的长度字段收满整帧。
//
// 收满整帧是关键：TCP 是字节流，一次 Read 可能只给半个帧，也可能一次给两帧 ——
// 只按"读一次"来解析是这类客户端最常见的 bug（表现为偶发地读错寄存器）。
func (c *Client) readFrameLocked(wantTxID uint16) ([]byte, error) {
	deadline := time.Now().Add(c.cfg.responseTimeout())

	head := make([]byte, mbapLen)
	if err := c.readFullLocked(head, deadline); err != nil {
		return nil, err
	}
	if head[2] != 0 || head[3] != 0 {
		return nil, fmt.Errorf("modbus_tcp: 协议号不是 0（收到 %02X%02X）", head[2], head[3])
	}
	if tx := binary.BigEndian.Uint16(head[0:2]); tx != wantTxID {
		return nil, fmt.Errorf("modbus_tcp: 事务号不符 期望 %d 收到 %d（这条连接上可能有多余数据）", wantTxID, tx)
	}
	length := int(binary.BigEndian.Uint16(head[4:6]))
	if length < 2 || length > maxPDU {
		return nil, fmt.Errorf("modbus_tcp: 长度字段不合理（%d）", length)
	}
	// 长度字段包含单元号，PDU 实际是 length-1 字节
	body := make([]byte, length-1)
	if err := c.readFullLocked(body, deadline); err != nil {
		return nil, err
	}
	return body, nil
}

func (c *Client) readFullLocked(buf []byte, deadline time.Time) error {
	got := 0
	for got < len(buf) {
		if !time.Now().Before(deadline) {
			return fmt.Errorf("%w（已收 %d/%d 字节）", ErrTimeout, got, len(buf))
		}
		n, err := c.conn.Read(buf[got:])
		if n > 0 {
			got += n
			continue
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				return errors.New("modbus_tcp: 连接被对端关闭")
			}
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				// 读超时：继续等，直到整体时限到（ReadDeadline 是每次设置的）
				_ = c.conn.SetReadDeadline(deadline)
				continue
			}
			return fmt.Errorf("modbus_tcp: 接收失败 %w", err)
		}
	}
	return nil
}

func (c *Client) ensureConnLocked() error {
	if c.conn != nil {
		return nil
	}
	conn, err := net.DialTimeout("tcp", c.cfg.addr(), c.cfg.connectTimeout())
	if err != nil {
		return fmt.Errorf("modbus_tcp: 连接 %s 失败 %w", c.cfg.addr(), err)
	}
	// 注意：这里**不**设 SetDeadline。Go 的 deadline 是绝对时刻，连上时设一次的话，
	// 连接空闲超过那个时长之后下一次 Write 就会立刻超时失败 —— 表现为"每 N 秒必失败一次"
	// 这种极有规律的假故障（实测踩到过：轮询周期 400ms、超时 2 秒，正好每 5 次挂 1 次）。
	// deadline 由每次交易的 transact 按当下时间重设。
	c.conn = conn
	return nil
}

func (c *Client) closeLocked() error {
	if c.conn == nil {
		return nil
	}
	err := c.conn.Close()
	c.conn = nil
	return err
}

func (c *Client) trace(format string, args ...any) {
	if c.cfg.Trace != nil {
		c.cfg.Trace(format, args...)
	}
}
