// Package modbus_rtu 是 Modbus RTU（串口）主站客户端：组帧、CRC、收发、超时、异常应答与重试。
//
// 它有意做成**一个普通主站**，而不是把所有抗干扰手段都堆进来：
//
//	组帧 → 发 → 按应答声明的字节数收齐一帧 → 校验 → 不对就重发（Retries 次）
//
// 时限只有一个：发完请求到收齐整帧（含从站的处理时间）。校验只有四项：CRC、从站号、
// 功能码、字节数。失败的处理只有一条：重试。抗干扰的主战场在物理层（隔离、屏蔽、
// 走线），软件这边要的只是"偶发坏帧不至于丢掉一次采样"。
//
// 只有一条额外纪律：**每次发帧前清一次接收缓冲**。RTU 没有帧定界符，靠时间间隔定界，
// 上一轮没收干净的残渣会让这一轮从帧中间开始读 —— 现场日志里那些"应答从站号不符
// 期望 1 收到 9"（0x09 是制表符）、"无法判定应答长度的功能码 0x20"（0x20 是空格）
// 就是错位的残渣，协议里根本不会出现这两个字节。每次事务都从干净的缓冲开始，重试才
// 救得回来：否则残渣会跟着毁掉每一次重试。
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

	// readSliceMS 是单次 Read 的最长等待。收帧靠"整帧时限 + 小步读"推进，
	// 这个值给小一点即可，不必等于整帧时间。
	readSliceMS = 30
)

// ErrTimeout 表示在时限内没有收齐一帧。上层据此做去重与重连。
var ErrTimeout = errors.New("modbus: 等待应答超时")

// ExceptionError 是从站回的异常应答（功能码最高位置 1）。
//
// 异常码含义各厂家不完全一致：这里只按标准 Modbus 给一个通用说法，排障时以设备手册为准
// （例如伟创 AC320 手册里 1 = 命令代码错误、3 = CRC 校验错误、11 = 读取参数字节数有误，
// 与下面这张标准表不是一回事）。
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

	// ResponseTimeoutMS 是**整帧时限**：从发完请求到收齐一帧（0 = 自动）。
	//
	// 它包含从站的处理时间（变频器这类 100~200ms 很常见），自动值取 500ms 与
	// 2 倍整帧传输时间中的较大者。现场量到设备确实回得慢就往上加；反过来，
	// 想更快发现掉线可以往下调（代价是偶发慢回话会被当成失败）。
	ResponseTimeoutMS int
	// Retries 是一笔事务失败后的额外重试次数（0 = 只发一次）。
	//
	// 读寄存器重试是幂等的；06H 写单个寄存器也幂等（同一个值写两次结果相同），
	// 所以这一层不对读写做区分。代价是最坏情况下一次事务花掉 (Retries+1) 倍时限。
	Retries int
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
	if cfg.Retries < 0 {
		cfg.Retries = 0
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
	// 字节数已在 checkResponse 里核对过，与请求的寄存器个数一致。
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

// transact 是唯一的收发出入口：发一帧、收一帧、校验；不对就重发，最多 Retries 次。
// 全程持锁，保证同一条串口上不会有两帧交叉。
//
// 一次尝试只有三个动作：等一个帧间静默、清一次接收缓冲、写请求，然后收一帧。
// 收发失败（超时、CRC 错、从站号/功能码/长度不符）都只做一件事 —— 再来一次。
// 不做"收坏了顺手补救"（清缓冲、关掉重开、按残渣重新对齐）：那类补救会让代码越写越厚，
// 而它们的活儿已经被"每次发帧前清一次 + 重试"覆盖了。
//
// 唯一的例外是**写请求失败**（串口句柄坏了、被别的进程占用）：那不是线上的噪声，
// 重试没有意义，直接返回错误，交给上层下一轮轮询。
func (c *Client) transact(req []byte, slave, fn byte, count int) ([]byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.cfg.PortName == "" {
		return nil, errors.New("modbus: 未配置串口号")
	}
	if err := c.openLocked(); err != nil {
		return nil, err
	}

	var lastErr error
	for attempt := 0; attempt <= c.cfg.Retries; attempt++ {
		c.waitSilence()
		c.flushRxLocked()

		if _, err := c.port.Write(req); err != nil {
			return nil, fmt.Errorf("modbus: 发送失败 %w", err)
		}
		c.lastWrite = time.Now()
		c.trace("TX %s", hex.EncodeToString(req))

		resp, err := c.readFrame(count)
		if err == nil {
			err = checkResponse(resp, slave, fn, count)
		}
		if err == nil {
			c.trace("RX %s", hex.EncodeToString(resp))
			return resp, nil
		}

		lastErr = err
		if attempt < c.cfg.Retries {
			c.trace("第 %d 次失败，重发：%v", attempt+1, err)
		}
	}
	return nil, lastErr
}

// checkResponse 校验一帧应答：长度、CRC、从站号、功能码（含异常应答）、字节数。
//
// **先验 CRC**：帧没通过校验之前，里面的从站号、功能码、字节数都不可信 ——
// 先看它们的话，CRC 失败的帧会被报成"从站号不符"或"字节数不符"，排障时会往错的方向查。
func checkResponse(resp []byte, slave, fn byte, count int) error {
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
	// 读应答的字节数必须与请求的寄存器个数一致。
	// 长度不对就说明这不是本笔的回话（迟到的、或别的一笔的应答也有合法 CRC）——
	// 照收的话会把它的数据当成这一笔的读数，甚至让上层按错误的长度取下标。
	if (fn == FuncReadHolding || fn == FuncReadInput) && int(resp[2]) != 2*count {
		return fmt.Errorf("modbus: 应答字节数不符 期望 %d 个寄存器（%d 字节）收到 %d 字节 % X",
			count, 2*count, resp[2], resp)
	}
	return nil
}

// readFrame 收一帧：整帧只有一个时限（从发完请求起算，含从站的处理时间）。
//
// 收帧分两步是协议决定的：应答的前 3 个字节（从站、功能码、异常码或字节数）决定了
// 这一帧还有多长 —— RTU 没有长度字段，只能这么读。
func (c *Client) readFrame(count int) ([]byte, error) {
	deadline := time.Now().Add(c.responseTimeout(count))

	head, err := c.readBytes(2, deadline)
	if err != nil {
		return nil, err
	}
	// 异常应答：从站 功能码|0x80 异常码 CRC CRC（共 5 字节）
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
		want = 6 // 地址 2 + 值 2 + CRC 2（应答是请求的回显，没有"字节数"这一位）
	default:
		return nil, fmt.Errorf("modbus: 应答功能码 0x%02X 不像本包的应答（像残渣错位）% X", head[1], head)
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
		ReadTimeout: readSliceMS * time.Millisecond,
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

// flushRxLocked 丢掉接收缓冲里残留的字节（不清发送方向）。
// 这是"帧对齐"的关键一步：残留的半帧会让下一次收发从帧中间开始读。
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

// waitSilence 等够一个帧间静默（3.5 个字符）。
//
// Modbus 要求两帧之间留这个间隔，从站才能把上一帧断开、把这一帧当成新帧的地址域。
// 上一次写到现在不够就补上；重试之间也走它，顺便让从站把上一帧的余波发完 ——
// 半双工总线上"我方已开始发、从站还在发"的撞车，从站看到的就是一帧坏报文。
func (c *Client) waitSilence() {
	if c.lastWrite.IsZero() {
		return
	}
	if wait := c.silenceGap() - time.Since(c.lastWrite); wait > 0 {
		time.Sleep(wait)
	}
}

// silenceGap 是 Modbus 要求的帧间静默时间（3.5 个字符）。
// 波特率高于 19200 时规范固定取 1.75ms。
func (c *Client) silenceGap() time.Duration {
	if c.cfg.BaudRate > 19200 {
		return 1750 * time.Microsecond
	}
	return time.Duration(float64(frameSilenceBits)*float64(time.Second)/float64(c.cfg.BaudRate)) + time.Millisecond
}

// responseTimeout 是整帧时限：从站的处理时间 + 一帧的传输时间。
//
// 自动值取 500ms 与 2 倍整帧时间中的较大者：前者管"从站慢"（设备处理时间不可预知），
// 后者管"帧长"（2400 波特读 100 个寄存器，光传就要 870ms，固定 500ms 根本不够）。
func (c *Client) responseTimeout(count int) time.Duration {
	if c.cfg.ResponseTimeoutMS > 0 {
		return time.Duration(c.cfg.ResponseTimeoutMS) * time.Millisecond
	}
	d := 2 * frameDuration(c.cfg.BaudRate, count)
	if d < 500*time.Millisecond {
		d = 500 * time.Millisecond
	}
	return d
}

// frameDuration 是一帧大约要传多久：报文长度按 5 + 2×寄存器数 估
// （从站号 + 功能码 + 字节数 + 数据 + CRC），一个字节 10 位，再加 3.5 个字符的帧间静默。
func frameDuration(baudRate, count int) time.Duration {
	if baudRate <= 0 {
		baudRate = 9600
	}
	bits := (5+2*count)*10 + frameSilenceBits
	return time.Duration(bits) * time.Second / time.Duration(baudRate)
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
