// Package modbus_rtu 是 Modbus RTU（串口）主站客户端：组帧、CRC、收发、超时与异常应答。
//
// 只覆盖桌面应用用得到的部分：读保持/输入寄存器（03H / 04H）与写单个寄存器（06H）。
// 不做 ASCII 模式、不实现写多个寄存器（10H）、不做 Modbus 网关转发。
//
// 帧格式与 CRC 按 Modbus 规范，CRC 低字节在前 —— 与各家手册的示例报文一致，例如
// 读从站 1 的 0x2100 起 3 个寄存器，发 [01 03 21 00 00 03 0F F7]（见 AC320 手册附录一）。
package modbus_rtu

import (
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/tarm/serial"
)

// 功能码。0x80 位在应答里表示异常。
const (
	FuncReadHolding  byte = 0x03
	FuncReadInput    byte = 0x04
	FuncWriteSingle  byte = 0x06
	fExceptionFlag   byte = 0x80
	frameSilenceBits      = 35 // 3.5 个字符：每字符 1 起始 + 8 数据 + 1 停止
)

// ErrTimeout 表示在等待时限内没有收齐一帧。上层据此做去重与重连。
var ErrTimeout = errors.New("modbus: 等待应答超时")

// ExceptionError 是从站回的异常应答（功能码最高位置 1）。
//
// 异常码含义各厂家不完全一致：这里只按标准 Modbus 给一个通用说法，排障时以设备手册为准
// （例如伟创 AC320 手册里 1 = 命令代码错误、11 = 读取参数字节数有误）。
type ExceptionError struct {
	Func byte
	Code byte
}

func (e *ExceptionError) Error() string {
	const std = "标准 Modbus 未定义该码"
	text := map[byte]string{
		0x01: "非法功能码",
		0x02: "非法数据地址",
		0x03: "非法数据值",
		0x04: "从站设备故障",
		0x05: "确认（从站已受理，需继续轮询）",
		0x06: "从站忙",
	}[e.Code]
	if text == "" {
		text = std
	}
	return fmt.Sprintf("modbus: 从站异常应答 功能码 0x%02X 异常码 0x%02X（%s）", e.Func, e.Code, text)
}

// Config 是一路串口的参数。通信参数必须与从站一致，否则收不到应答。
type Config struct {
	PortName string
	BaudRate int
	// DataBits 为 0 表示 8 位数据。
	DataBits int
	// Parity 取 "N" / "E" / "O"，空表示无校验。
	Parity string
	// StopBits 为 0 表示 1 位停止位。
	StopBits int

	// ReadTimeoutMS 是单次 Read 的最长等待。收发循环靠"整体时限 + 小步读"推进，
	// 这个值给小一点（默认 30ms）即可，不需要等于整帧时间。
	ReadTimeoutMS int
	// ResponseTimeoutMS 是从站回一帧的上限；为 0 时按波特率与寄存器个数估算。
	ResponseTimeoutMS int
	// Trace 非空时回调每次收发的十六进制原文，用于现场排障。
	Trace func(format string, args ...any)
}

func (cfg Config) withDefaults() Config {
	if cfg.DataBits <= 0 || cfg.DataBits > 8 {
		cfg.DataBits = 8
	}
	if cfg.StopBits <= 0 {
		cfg.StopBits = 1
	}
	if cfg.Parity == "" {
		cfg.Parity = "N"
	}
	if cfg.BaudRate <= 0 {
		cfg.BaudRate = 9600
	}
	if cfg.ReadTimeoutMS <= 0 {
		cfg.ReadTimeoutMS = 30
	}
	return cfg
}

// Client 是一路 Modbus RTU 总线（一个串口）的客户端。
// 方法自带互斥，可被多个 goroutine 调用；但同一条总线上多从站的报文必须串行发，
// 因此更稳妥的做法是每个从站一个 worker、各自持有自己的 Client。
type Client struct {
	mu        sync.Mutex
	cfg       Config
	port      io.ReadWriteCloser
	lastWrite time.Time
}

// New 建立客户端，此时并不打开串口（首次收发时自动打开）。
func New(cfg Config) *Client { return &Client{cfg: cfg.withDefaults()} }

// SetConfig 换一套串口参数；下一次收发时按新参数重开串口。
func (c *Client) SetConfig(cfg Config) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.closeLocked()
	c.cfg = cfg.withDefaults()
	c.lastWrite = time.Time{}
}

// PortName 返回当前串口号（配置页显示用）。
func (c *Client) PortName() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.cfg.PortName
}

// IsOpen 报告串口当前是否打开。
func (c *Client) IsOpen() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.port != nil
}

// Open 打开串口。已打开则直接返回。
func (c *Client) Open() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.openLocked()
}

// Close 关闭串口，可重复调用。
func (c *Client) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.closeLocked()
}

// ReadHoldingRegisters 读保持寄存器（0x03）。
func (c *Client) ReadHoldingRegisters(slave byte, addr, count uint16) ([]uint16, error) {
	return c.ReadRegisters(slave, FuncReadHolding, addr, count)
}

// ReadInputRegisters 读输入寄存器（0x04）。
func (c *Client) ReadInputRegisters(slave byte, addr, count uint16) ([]uint16, error) {
	return c.ReadRegisters(slave, FuncReadInput, addr, count)
}

// ReadRegisters 按功能码读寄存器。count 为 1~125（Modbus 对一帧的字节数限制）。
func (c *Client) ReadRegisters(slave, fn byte, addr, count uint16) ([]uint16, error) {
	if fn != FuncReadHolding && fn != FuncReadInput {
		return nil, fmt.Errorf("modbus: 不支持的功能码 0x%02X", fn)
	}
	if err := checkBatch(count); err != nil {
		return nil, err
	}

	req := []byte{slave, fn, byte(addr >> 8), byte(addr), byte(count >> 8), byte(count)}
	req = appendCRC(req)

	resp, err := c.transact(req, slave, fn, int(count))
	if err != nil {
		return nil, err
	}
	// resp: 从站 功能码 字节数 数据... CRC CRC
	n := int(resp[2]) / 2
	out := make([]uint16, n)
	for i := 0; i < n; i++ {
		out[i] = uint16(resp[3+2*i])<<8 | uint16(resp[4+2*i])
	}
	return out, nil
}

// WriteSingleRegister 写单个保持寄存器（0x06）。
func (c *Client) WriteSingleRegister(slave byte, addr, value uint16) error {
	req := []byte{slave, FuncWriteSingle, byte(addr >> 8), byte(addr), byte(value >> 8), byte(value)}
	req = appendCRC(req)

	resp, err := c.transact(req, slave, FuncWriteSingle, 0)
	if err != nil {
		return err
	}
	// 应答是请求的原样回显（地址 + 写入值）
	if len(resp) < 8 {
		return fmt.Errorf("modbus: 写应答过短 %d 字节", len(resp))
	}
	if resp[2] != req[2] || resp[3] != req[3] || resp[4] != req[4] || resp[5] != req[5] {
		return fmt.Errorf("modbus: 写应答回显不一致 % X != % X", resp[2:6], req[2:6])
	}
	return nil
}

// transact 是唯一的收发出入口：发一帧、收一帧、校验。
// 全程持锁，保证同一条串口上不会有两帧交叉。
func (c *Client) transact(req []byte, slave, fn byte, count int) ([]byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.cfg.PortName == "" {
		return nil, errors.New("modbus: 未配置串口号")
	}
	if err := c.openLocked(); err != nil {
		return nil, err
	}
	c.trace("TX %s", hex.EncodeToString(req))

	// 帧间静默：上一帧的收尾与这一帧的起始之间要留 3.5 个字符的时间，
	// 从站才能把上一帧断开、把这一帧当成新帧的地址域。
	if gap := c.silenceGap(); !c.lastWrite.IsZero() {
		if wait := gap - time.Since(c.lastWrite); wait > 0 {
			time.Sleep(wait)
		}
	}

	if _, err := c.port.Write(req); err != nil {
		c.reopenLocked()
		return nil, fmt.Errorf("modbus: 发送失败 %w", err)
	}
	c.lastWrite = time.Now()

	deadline := time.Now().Add(c.responseTimeout(count))
	resp, err := c.readFrame(deadline)
	if err != nil {
		// 收不到应答往往意味着线序/参数不对或从站掉线，重开一次让下一次干净开始
		c.reopenLocked()
		return nil, err
	}
	c.trace("RX %s", hex.EncodeToString(resp))

	if resp[0] != slave {
		return nil, fmt.Errorf("modbus: 应答从站号不符 期望 %d 收到 %d", slave, resp[0])
	}
	if resp[1] == fn|fExceptionFlag {
		if len(resp) < 5 {
			return nil, fmt.Errorf("modbus: 异常应答过短 %d 字节", len(resp))
		}
		return nil, &ExceptionError{Func: fn, Code: resp[2]}
	}
	if resp[1] != fn {
		return nil, fmt.Errorf("modbus: 应答功能码不符 期望 0x%02X 收到 0x%02X", fn, resp[1])
	}
	if !validCRC(resp) {
		return nil, fmt.Errorf("modbus: 应答 CRC 校验失败 % X", resp)
	}
	if (fn == FuncReadHolding || fn == FuncReadInput) && len(resp) < 3 {
		return nil, fmt.Errorf("modbus: 读应答过短 %d 字节", len(resp))
	}
	return resp, nil
}

// readFrame 按功能码应收的长度收一帧。
//
// 收不到数据时 tarm/serial 的 Read 在 Windows 上会返回错误，这里靠 err 判断并不方便，
// 因此沿用仓库里已验证的写法：忽略错误、只看读到的字节数，配合整体时限轮询。
func (c *Client) readFrame(deadline time.Time) ([]byte, error) {
	head, err := c.readBytes(2, deadline)
	if err != nil {
		return nil, err
	}
	// 异常应答：从站 功能码|0x80 异常码 CRC CRC
	if head[1]&fExceptionFlag != 0 {
		rest, err := c.readBytes(3, deadline)
		if err != nil {
			return nil, err
		}
		return append(head, rest...), nil
	}

	var want int
	switch head[1] {
	case FuncReadHolding, FuncReadInput:
		// 字节数占 1 字节，长度要读到它才知道
		one, err := c.readBytes(1, deadline)
		if err != nil {
			return nil, err
		}
		head = append(head, one...)
		want = int(one[0]) + 2 // 数据 + CRC
	case FuncWriteSingle:
		want = 6 // 地址 2 + 值 2 + CRC 2（应答是请求的回显）
	default:
		return nil, fmt.Errorf("modbus: 无法判定应答长度的功能码 0x%02X", head[1])
	}

	rest, err := c.readBytes(want, deadline)
	if err != nil {
		return nil, err
	}
	return append(head, rest...), nil
}

// readBytes 在时限内读满 n 个字节。
func (c *Client) readBytes(n int, deadline time.Time) ([]byte, error) {
	buf := make([]byte, 0, n)
	tmp := make([]byte, n)
	for len(buf) < n {
		if !time.Now().Before(deadline) {
			return nil, fmt.Errorf("%w（已收 %d/%d 字节）", ErrTimeout, len(buf), n)
		}
		m, _ := c.port.Read(tmp[:n-len(buf)])
		if m > 0 {
			buf = append(buf, tmp[:m]...)
			continue
		}
		// 一次 Read 没拿到字节就歇一下，避免空转烧 CPU
		time.Sleep(2 * time.Millisecond)
	}
	return buf, nil
}

func (c *Client) openLocked() error {
	if c.port != nil {
		return nil
	}
	// 串口号按配置原样交给串口库：它在 Windows 上自己会补 \\.\ 前缀（COM10 以上也能开）
	p, err := serial.OpenPort(&serial.Config{
		Name:        c.cfg.PortName,
		Baud:        c.cfg.BaudRate,
		Size:        byte(c.cfg.DataBits),
		Parity:      serial.Parity(c.cfg.Parity[0]),
		StopBits:    serial.StopBits(c.cfg.StopBits),
		ReadTimeout: time.Duration(c.cfg.ReadTimeoutMS) * time.Millisecond,
	})
	if err != nil {
		return fmt.Errorf("modbus: 打开串口 %s 失败 %w", c.cfg.PortName, err)
	}
	c.port = p
	return nil
}

func (c *Client) closeLocked() error {
	if c.port == nil {
		return nil
	}
	err := c.port.Close()
	c.port = nil
	return err
}

// reopenLocked 关掉再打开，并清空接收缓冲：上一次失败的半帧不能留到下一次。
func (c *Client) reopenLocked() {
	_ = c.closeLocked()
	if err := c.openLocked(); err != nil {
		c.trace("重新打开串口失败: %v", err)
		return
	}
	c.drainLocked()
}

func (c *Client) drainLocked() {
	if c.port == nil {
		return
	}
	buf := make([]byte, 256)
	for {
		n, err := c.port.Read(buf)
		if n == 0 || err != nil {
			return
		}
	}
}

// responseTimeout 估算"从站处理 + 回一帧"需要多久，再留 3 倍余量。
// 2400bps 读 25 个寄存器要 ~260ms 才传得完，时限给紧了会误判超时。
func (c *Client) responseTimeout(count int) time.Duration {
	if c.cfg.ResponseTimeoutMS > 0 {
		return time.Duration(c.cfg.ResponseTimeoutMS) * time.Millisecond
	}
	bytes := 5 + 2*count
	nanos := int64(bytes*10+frameSilenceBits) * int64(time.Second) / int64(c.cfg.BaudRate)
	d := time.Duration(nanos) * 3
	if d < 200*time.Millisecond {
		d = 200 * time.Millisecond
	}
	return d
}

// silenceGap 是 Modbus 要求的帧间静默时间（3.5 个字符）。
// 波特率高于 19200 时规范固定取 1.75ms。
func (c *Client) silenceGap() time.Duration {
	if c.cfg.BaudRate > 19200 {
		return 1750 * time.Microsecond
	}
	return time.Duration(float64(frameSilenceBits)*float64(time.Second)/float64(c.cfg.BaudRate)) + time.Millisecond
}

func (c *Client) trace(format string, args ...any) {
	if c.cfg.Trace != nil {
		c.cfg.Trace(format, args...)
	}
}

func checkBatch(count uint16) error {
	if count == 0 || count > 125 {
		return fmt.Errorf("modbus: 一次读 %d 个寄存器超出 1~125 的范围", count)
	}
	return nil
}

// CRC16 返回标准的 Modbus CRC-16 值（多项式 0xA001，初值 0xFFFF）。
// 上帧时先低字节、后高字节；校验回帧时同样按这个顺序还原。
func CRC16(data []byte) uint16 {
	crc := uint16(0xFFFF)
	for _, b := range data {
		crc ^= uint16(b)
		for i := 0; i < 8; i++ {
			if crc&1 != 0 {
				crc = (crc >> 1) ^ 0xA001
			} else {
				crc >>= 1
			}
		}
	}
	return crc
}

func appendCRC(frame []byte) []byte {
	crc := CRC16(frame)
	return append(frame, byte(crc), byte(crc>>8))
}

func validCRC(frame []byte) bool {
	if len(frame) < 3 {
		return false
	}
	body := frame[:len(frame)-2]
	want := uint16(frame[len(frame)-1])<<8 | uint16(frame[len(frame)-2])
	return CRC16(body) == want
}
