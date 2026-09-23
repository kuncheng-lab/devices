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
	// ResponseTimeoutMS 覆盖"等从站开头的字节送回来"的时限（0 = 自动）。
	//
	// 它只管**从站的处理时间**这一段：首字节到了之后，余下字节按字节数另给预算
	// （见 firstByteTimeout / tailTimeout）。自动值 = 500ms 与 2 倍整帧传输时间中的较大者。
	// 现场量到设备的实际处理时间后，填它的 2~3 倍即可。
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

// serialPort 是收发需要的最小串口能力：tarm/serial 的 *Port 满足它（测试里用内存替身）。
//
// Flush 用来丢弃接收缓冲里残留的字节 —— Windows 上 tarm/serial 把它实现为
// PurgeComm（含 PURGE_RXCLEAR）。少了这一步，上一轮没收干净的小尾巴会留在缓冲里，
// 下一轮就从帧中间开始读（见 transact 的说明）。
type serialPort interface {
	io.ReadWriteCloser
	Flush() error
}

// Client 是一路 Modbus RTU 总线（一个串口）的客户端。
// 方法自带互斥，可被多个 goroutine 调用；但同一条总线上多从站的报文必须串行发，
// 因此更稳妥的做法是每个从站一个 worker、各自持有自己的 Client。
type Client struct {
	mu        sync.Mutex
	cfg       Config
	port      serialPort
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
//
// 三条"清接收缓冲"的纪律，都是现场日志逼出来的：
//
//  1. **发帧前清一次**。上一轮没收干净的小尾巴（超时的半帧、被丢弃的迟到应答）如果留着，
//     这一轮就会从帧中间开始读。现场日志里那些不像 Modbus 的字节就是残渣被当成帧头：
//     "应答从站号不符 期望 1 收到 9"（0x09 是制表符）、"无法判定应答长度的功能码 0x20"
//     （0x20 是空格）—— 协议里都不会出现这两个字节，只可能是错位。
//  2. **校验不过也要清**。CRC / 从站号 / 功能码不符时，这一帧剩下的部分同样不能留给下一轮，
//     否则一次坏帧会连累后面好几轮（现场是一错就连着一串）。
//  3. **超时或发不出去**：关掉串口重开。只有关闭句柄才能取消驱动里那个没回来的重叠读。
//
// 为什么晚到的应答也会变成残渣：从站回得比"轮询周期 + 时限"还慢时，它属于上一轮的应答会在
// 这一轮才进入缓冲。清掉它比收下它更安全 —— 它对应的是已经放弃的那一轮。
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
	c.flushRxLocked() // 纪律 1

	if _, err := c.port.Write(req); err != nil {
		c.reopenLocked()
		return nil, fmt.Errorf("modbus: 发送失败 %w", err)
	}
	c.lastWrite = time.Now()

	resp, err := c.readFrame(count)
	if err != nil {
		// 收不到应答往往意味着线序/参数不对或从站掉线，重开一次让下一次干净开始（纪律 3）
		c.reopenLocked()
		return nil, err
	}
	c.trace("RX %s", hex.EncodeToString(resp))

	if err := checkResponse(resp, slave, fn); err != nil {
		c.flushRxLocked() // 纪律 2
		return nil, err
	}
	return resp, nil
}

// checkResponse 校验一帧应答：长度、CRC、从站号、功能码（含异常应答）。
//
// **先验 CRC**：帧没通过校验之前，里面的从站号与功能码都不可信 ——
// 先看从站号的话，CRC 失败的帧会被报成"从站号不符"，排障时会往错的方向查。
func checkResponse(resp []byte, slave, fn byte) error {
	// 最短的合法帧是 5 字节：从站 功能码 异常码 CRC CRC
	if len(resp) < 5 {
		return fmt.Errorf("modbus: 应答过短 %d 字节 % X", len(resp), resp)
	}
	if !validCRC(resp) {
		return fmt.Errorf("modbus: 应答 CRC 校验失败 % X", resp)
	}
	if resp[0] != slave {
		return fmt.Errorf("modbus: 应答从站号不符 期望 %d 收到 %d", slave, resp[0])
	}
	if resp[1] == fn|fExceptionFlag {
		return &ExceptionError{Func: fn, Code: resp[2]}
	}
	if resp[1] != fn {
		return fmt.Errorf("modbus: 应答功能码不符 期望 0x%02X 收到 0x%02X", fn, resp[1])
	}
	return nil
}

// readFrame 收一帧：先等首字节，再按帧长把余下的字节收完。
//
// 时限**拆成两段**是有原因的：整帧共用一个截止时间时，"从站什么时候才开始回"（处理时间，
// 不可预知）与"回一帧要传多久"（与波特率和字节数有关）挤在同一个预算里。设备处理慢一点
// （变频器这类 100~200ms 很常见）就会在差最后一两个字节时超时 ——
// 现场日志里的"等待应答超时（已收 29/30 字节）"就是这么来的：等首字节吃掉了大半预算，
// 剩下的时间不够传完，于是每次都差一个字节，而那一两个字节留在缓冲里又污染下一轮。
//
// 首字节一到，余下的就是纯传输时间，按字节数单独给预算即可（见 tailTimeout）。
func (c *Client) readFrame(count int) ([]byte, error) {
	head, err := c.readBytes(2, time.Now().Add(c.firstByteTimeout(count)))
	if err != nil {
		return nil, err
	}
	// 异常应答：从站 功能码|0x80 异常码 CRC CRC
	if head[1]&fExceptionFlag != 0 {
		rest, err := c.readBytes(3, time.Now().Add(c.tailTimeout(3)))
		if err != nil {
			return nil, err
		}
		return append(head, rest...), nil
	}

	var want int
	switch head[1] {
	case FuncReadHolding, FuncReadInput:
		// 字节数占 1 字节，长度要读到它才知道
		one, err := c.readBytes(1, time.Now().Add(c.tailTimeout(1)))
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

	rest, err := c.readBytes(want, time.Now().Add(c.tailTimeout(want)))
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

// flushRxLocked 丢掉接收缓冲里残留的字节（不清发送方向）。
// 这是"帧对齐"的关键一步：残留的半个帧头会让下一次收发从帧中间开始读。
//
// 失败只记 trace、不影响本次收发：清不掉缓冲最坏也就是退化成原来的行为，
// 不该因此把一次可能成功的读取判死。
func (c *Client) flushRxLocked() {
	if c.port == nil {
		return
	}
	if err := c.port.Flush(); err != nil {
		c.trace("清接收缓冲失败: %v", err)
	}
}

// ---- 时限 ------------------------------------------------------------------

// frameDuration 是一帧大约要传多久：报文长度按 5 + 2×寄存器数 估
// （从站号 + 功能码 + 字节数 + 数据 + CRC），一个字节 10 位，再加 3.5 个字符的帧间静默。
func frameDuration(baudRate, count int) time.Duration {
	if baudRate <= 0 {
		baudRate = 9600
	}
	bits := (5+2*count)*10 + frameSilenceBits
	return time.Duration(bits) * time.Second / time.Duration(baudRate)
}

// firstByteTimeout 是"发完请求、等从站把开头的字节送回来"的上限。
//
// 这一段装的是**从站的处理时间**，而它不可预知（变频器常见 100~200ms，更慢的也有），
// 所以给得比整帧传输时间宽：取 500ms 与 2 倍整帧时间中的较大者。
// 现场如果量到了设备的实际处理时间，用 ResponseTimeoutMS 直接覆盖这一段（填处理时间的 2~3 倍）。
func (c *Client) firstByteTimeout(count int) time.Duration {
	if c.cfg.ResponseTimeoutMS > 0 {
		return time.Duration(c.cfg.ResponseTimeoutMS) * time.Millisecond
	}
	d := 2 * frameDuration(c.cfg.BaudRate, count)
	if d < 500*time.Millisecond {
		d = 500 * time.Millisecond
	}
	return d
}

// tailTimeout 是"首字节已到、还要再收 n 个字节"的上限。
// 这一段是纯传输时间，按字节数给：4 倍余量（USB 转串口有毫秒级的包间隔），下限 60ms。
func (c *Client) tailTimeout(n int) time.Duration {
	if n <= 0 {
		n = 1
	}
	baud := c.cfg.BaudRate
	if baud <= 0 {
		baud = 9600
	}
	d := time.Duration(4*n*10) * time.Second / time.Duration(baud)
	if d < 60*time.Millisecond {
		d = 60 * time.Millisecond
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
