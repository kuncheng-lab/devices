package modbus_rtu

import (
	"encoding/hex"
	"errors"
	"sync"
	"testing"
	"time"
)

// CRC 的正确性靠外部权威向量锚定，不靠自己的实现对拍：
//   - "123456789" 的 CRC-16/MODBUS 校验值是 0x4B37（该算法的标准 check 值）；
//   - AC320 手册附录一给了请求帧与异常应答帧的完整报文（含 CRC 字节）；
//   - 仓库里 modbus_rfid 的既有测试给了一帧 RFID 读请求（另一套独立实现）。
//
// 手册的"正常应答"示例帧（01 03 06 13 88 00 00 00 00 90 A6）自相矛盾：
// 按它的报文正文算出来的 CRC 是 C3 C9，不是 90 A6。同一页的请求帧与异常帧都能对上，
// 所以按手册写错了这帧 CRC 处理，行为测试里改用算出来的帧。
func TestCRC16CheckValue(t *testing.T) {
	if got := CRC16([]byte("123456789")); got != 0x4B37 {
		t.Fatalf("CRC-16/MODBUS 校验值 期望 0x4B37 实际 0x%04X", got)
	}
}

func TestCRC16MatchesVendorFrames(t *testing.T) {
	cases := []struct {
		name string
		body string // 不含 CRC 的报文
		crc  string // 手册/既有测试给出的 CRC 字节，按上线顺序
	}{
		{"AC320 手册 请求帧", "010321000003", "0ff7"},
		{"AC320 手册 异常应答帧", "018304", "40f3"},
		{"modbus_rfid 既有测试向量", "0103000a0019", "a402"},
	}
	for _, c := range cases {
		body, err := hex.DecodeString(c.body)
		if err != nil {
			t.Fatalf("%s: 用例本身写错了 %v", c.name, err)
		}
		crc := CRC16(body)
		got := hex.EncodeToString([]byte{byte(crc), byte(crc >> 8)})
		if got != c.crc {
			t.Fatalf("%s: CRC 期望 %s 实际 %s（低字节先上线的顺序）", c.name, c.crc, got)
		}
	}
}

func TestBuildReadRequestMatchesManual(t *testing.T) {
	c := newTestClient(&fakePort{})
	defer c.Close()

	// 与手册那一帧逐字节对照：从站 1、0x2100 起 3 个寄存器
	if got := hex.EncodeToString(appendCRC([]byte{0x01, 0x03, 0x21, 0x00, 0x00, 0x03})); got != "0103210000030ff7" {
		t.Fatalf("请求帧不符 实际 %s", got)
	}
}

func TestReadHoldingRegistersReturnsValues(t *testing.T) {
	// 手册应答帧的数据部分：0x1388 / 0x0000 / 0x0000
	fp := &fakePort{resp: readResponse(1, 0x1388, 0, 0)}
	c := newTestClient(fp)
	defer c.Close()

	got, err := c.ReadHoldingRegisters(1, 0x2100, 3)
	if err != nil {
		t.Fatalf("读取失败: %v", err)
	}
	want := []uint16{0x1388, 0, 0}
	if len(got) != len(want) {
		t.Fatalf("寄存器个数 期望 %d 实际 %d", len(want), len(got))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("第 %d 个寄存器 期望 0x%04X 实际 0x%04X", i, want[i], got[i])
		}
	}
	if sent := hex.EncodeToString(fp.sent()); sent != "0103210000030ff7" {
		t.Fatalf("发出的帧不符 实际 %s", sent)
	}
}

// 一次只给一个字节，验证按长度收帧的逻辑不依赖串口驱动一次给全。
func TestReadHoldingRegistersHandlesDribbledBytes(t *testing.T) {
	fp := &fakePort{resp: readResponse(1, 0x1388, 0, 0), chunk: 1}
	c := newTestClient(fp)
	defer c.Close()

	got, err := c.ReadHoldingRegisters(1, 0x2100, 3)
	if err != nil {
		t.Fatalf("读取失败: %v", err)
	}
	if len(got) != 3 || got[0] != 0x1388 {
		t.Fatalf("寄存器内容不对 % X", got)
	}
}

func TestReadHoldingRegistersException(t *testing.T) {
	// 手册的异常应答：功能码 0x83、异常码 4
	fp := &fakePort{resp: mustHex(t, "018304 40f3")}
	c := newTestClient(fp)
	defer c.Close()

	_, err := c.ReadHoldingRegisters(1, 0x2100, 3)
	var ex *ExceptionError
	if !errors.As(err, &ex) {
		t.Fatalf("期望 ExceptionError 实际 %v", err)
	}
	if ex.Code != 0x04 || ex.Func != FuncReadHolding {
		t.Fatalf("异常码不符 功能码 0x%02X 码 0x%02X", ex.Func, ex.Code)
	}
}

func TestReadHoldingRegistersRejectsBadCRC(t *testing.T) {
	frame := readResponse(1, 0x1388, 0, 0)
	frame[len(frame)-1] ^= 0xFF // 末字节改坏
	c := newTestClient(&fakePort{resp: frame})
	defer c.Close()

	if _, err := c.ReadHoldingRegisters(1, 0x2100, 3); err == nil {
		t.Fatal("CRC 错误却读成功了")
	}
}

func TestReadHoldingRegistersTimeout(t *testing.T) {
	c := newTestClient(&fakePort{}) // 从站不回话
	defer c.Close()

	_, err := c.ReadHoldingRegisters(1, 0x2100, 3)
	if !errors.Is(err, ErrTimeout) {
		t.Fatalf("期望超时 实际 %v", err)
	}
}

func TestReadHoldingRegistersRejectsWrongSlave(t *testing.T) {
	// 应答里的从站号是 2，我们问的是 1 —— 一条总线上挂多个从站时不能认错
	fp := &fakePort{resp: readResponse(2, 0x1388)}
	c := newTestClient(fp)
	defer c.Close()

	if _, err := c.ReadHoldingRegisters(1, 0x2100, 1); err == nil {
		t.Fatal("从站号不符却读成功了")
	}
}

func TestReadRegistersRejectsBadCount(t *testing.T) {
	c := newTestClient(&fakePort{})
	defer c.Close()

	for _, n := range []uint16{0, 126} {
		if _, err := c.ReadHoldingRegisters(1, 0, n); err == nil {
			t.Fatalf("count=%d 应被拒绝", n)
		}
	}
}

// 应答的字节数必须与请求的寄存器个数一致。
//
// 迟到的、或同一条总线上别的一笔的应答也有合法 CRC、站号与功能码也照样对得上，
// 长度是唯一能把它们区分开的东西 —— 照收的话上层会按错误的长度取下标
// （读 2 个却回 14 个，就会把监控组的数据当成状态区）。
func TestResponseLengthMustMatchRequest(t *testing.T) {
	// 问的是 2 个寄存器，回的却是 3 个（CRC、从站号、功能码都合法）
	fp := &fakePort{resp: readResponse(1, 0x2345, 0x1388, 0)}
	c := newTestClient(fp)
	defer c.Close()

	if _, err := c.ReadHoldingRegisters(1, 0x2002, 2); err == nil {
		t.Fatal("应答字节数与请求不符却读成功了")
	}
}

// 帧对齐与重试的回归测试（现场日志：一次坏帧会连累后面好几轮）。
//
// 残渣长什么样：现场出现过"应答从站号不符 期望 1 收到 9"（0x09 制表符）与
// "无法判定应答长度的功能码 0x20"（0x20 空格）—— 协议里不会有这两个字节，
// 只能是上一轮没收干净、这一轮从帧中间开始读。这里用同样"不像 Modbus"的字节当残渣。
//
// 现在对付残渣的只有一条纪律（每次发帧前清一次）加一条兜底（重试），两条都在这里钉住。
func TestStaleBytesAreFlushedBeforeSend(t *testing.T) {
	fp := &fakePort{
		preload: mustHex(t, "09201C0000"),      // 上一轮的残渣
		resp:    readResponse(1, 0x1388, 0, 0), // 这一轮真正的应答（发帧之后才到）
	}
	c := newTestClient(fp)
	defer c.Close()

	got, err := c.ReadHoldingRegisters(1, 0x2100, 3)
	if err != nil {
		t.Fatalf("残留字节没清掉，收帧从帧中间开始了: %v", err)
	}
	if len(got) != 3 || got[0] != 0x1388 {
		t.Fatalf("寄存器内容不对 % X", got)
	}
	if fp.flushCount() == 0 {
		t.Fatal("发帧前没有清接收缓冲")
	}
}

// 重试：第一帧被改坏、第二帧正常，一次事务里应当救回来 ——
// 现场的偶发毛刺就是靠它被吸收掉的，而不是丢掉这一拍采样。
func TestRetryAfterBadFrame(t *testing.T) {
	bad := readResponse(1, 0x1388, 0, 0)
	bad[len(bad)-1] ^= 0xFF // CRC 改坏
	fp := &fakePort{queue: [][]byte{bad, readResponse(1, 0x1388, 0, 0)}}
	c := newTestClient(fp)
	c.cfg.Retries = 1
	defer c.Close()

	got, err := c.ReadHoldingRegisters(1, 0x2100, 3)
	if err != nil {
		t.Fatalf("重试没救回来: %v", err)
	}
	if len(got) != 3 || got[0] != 0x1388 {
		t.Fatalf("寄存器内容不对 % X", got)
	}
	// 两次尝试 = 两帧请求（每个请求 8 字节）+ 发帧前各清一次接收缓冲。
	// 第二次清缓冲是重试能成功的前提：残渣会跟着毁掉每一次重试。
	if n := len(fp.sent()); n != 16 {
		t.Fatalf("发了 %d 字节，期望两帧共 16 字节", n)
	}
	if n := fp.flushCount(); n != 2 {
		t.Fatalf("清缓冲 %d 次，期望每帧前各一次（2 次）", n)
	}
}

// 重试用完就放弃：Retries=1 ⇒ 一共发两帧，错误原样交给上层（由上层决定要不要重连）。
func TestRetriesGiveUpAfterLimit(t *testing.T) {
	bad := readResponse(1, 0x1388, 0, 0)
	bad[len(bad)-1] ^= 0xFF // CRC 改坏
	fp := &fakePort{queue: [][]byte{bad, bad}}
	c := newTestClient(fp)
	c.cfg.Retries = 1
	defer c.Close()

	if _, err := c.ReadHoldingRegisters(1, 0x2100, 3); err == nil {
		t.Fatal("两帧都坏却读成功了")
	}
	if n := len(fp.sent()); n != 16 {
		t.Fatalf("发了 %d 字节，期望 Retries=1 时正好两帧（16 字节）", n)
	}
}

// 从站回得慢：整帧时限要等得住从站的处理时间。现场那种"已收 29/30 字节"的超时，
// 根子就是等首字节时把整帧预算耗光了。
func TestSlowDeviceStillReceives(t *testing.T) {
	fp := &fakePort{
		resp:  readResponse(1, 0x1388, 0, 0),
		delay: 300 * time.Millisecond, // 设备处理 300ms 才开始回
	}
	// ResponseTimeoutMS 留 0：走自动值（500ms 下限），它包含设备处理时间
	c := New(Config{PortName: "COM_TEST", BaudRate: 9600, Trace: func(string, ...any) {}})
	c.port = fp
	defer c.Close()

	got, err := c.ReadHoldingRegisters(1, 0x2100, 3)
	if err != nil {
		t.Fatalf("设备回得慢一读就超时: %v", err)
	}
	if len(got) != 3 || got[0] != 0x1388 {
		t.Fatalf("寄存器内容不对 % X", got)
	}
}

func TestWriteSingleRegisterEcho(t *testing.T) {
	fp := &fakePort{resp: appendCRC([]byte{0x01, 0x06, 0x21, 0x00, 0x00, 0x64})}
	c := newTestClient(fp)
	defer c.Close()

	if err := c.WriteSingleRegister(1, 0x2100, 0x0064); err != nil {
		t.Fatalf("写入失败: %v", err)
	}
	sent := fp.sent()
	// 帧体逐字节对照：从站 功能码 地址高位 地址低位 值高位 值低位
	if got := hex.EncodeToString(sent[:6]); got != "010621000064" {
		t.Fatalf("写帧帧体不符 实际 %s", got)
	}
	if !validCRC(sent) {
		t.Fatalf("写帧 CRC 不合法 % X", sent)
	}
}

func TestUnconfiguredPortNameIsRejected(t *testing.T) {
	c := New(Config{})
	defer c.Close()
	if _, err := c.ReadHoldingRegisters(1, 0, 1); err == nil {
		t.Fatal("没配串口号却读成功了")
	}
}

// ---- 测试替身与夹具 --------------------------------------------------------

func newTestClient(port *fakePort) *Client {
	// 时限只要够假串口把预置的字节吐完即可，测试里不真等。
	// Retries 留 0（只发一次）：需要重试的用例自己设，别的用例靠它把"发了几帧"数得清楚。
	c := New(Config{
		PortName:          "COM_TEST",
		BaudRate:          9600,
		ResponseTimeoutMS: 60,
		Trace:             func(string, ...any) {},
	})
	c.port = port // 绕过真实串口
	return c
}

// readResponse 按功能码 03 的应答格式组一帧：从站 功能码 字节数 数据... CRC CRC
func readResponse(slave byte, regs ...uint16) []byte {
	frame := []byte{slave, FuncReadHolding, byte(len(regs) * 2)}
	for _, r := range regs {
		frame = append(frame, byte(r>>8), byte(r))
	}
	return appendCRC(frame)
}

// fakePort 是内存里的串口：Write 记下来，Read 按 chunk 一片片吐出预置应答。
//
//	preload —— 构造时就"已经在缓冲里"的字节（模拟上一轮没收干净的残渣）。
//	resp    —— 发帧之后才到达的字节（正常的从站应答都走这里：真串口上应答不可能
//	              早于请求，而"发帧前清缓冲"正是要清掉 preload、留下 resp）。
//	queue   —— 与 resp 同理，但每次 Write 依次取一条：用来喂"第一次坏、第二次好"
//	              这种多帧序列（没有 queue 时 resp 发完第一次就成了空）。
//	delay   —— 从站的处理时间：Write 之后这么久内 Read 一律返回 0 字节。
type fakePort struct {
	mu      sync.Mutex
	rx      []byte
	offset  int
	chunk   int // 0 表示一次给完
	preload []byte
	resp    []byte
	queue   [][]byte
	delay   time.Duration
	writeAt time.Time
	flushes int
	writes  []byte
}

func (f *fakePort) Read(p []byte) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	// 从站还在处理：还没开始回话
	if f.delay > 0 && !f.writeAt.IsZero() && time.Since(f.writeAt) < f.delay {
		time.Sleep(time.Millisecond)
		return 0, nil
	}
	if f.offset >= len(f.rx) {
		// 没有数据了：真串口这里是等超时，返回 0 字节即可
		time.Sleep(time.Millisecond)
		return 0, nil
	}
	n := len(f.rx) - f.offset
	if f.chunk > 0 && n > f.chunk {
		n = f.chunk
	}
	if n > len(p) {
		n = len(p)
	}
	copy(p, f.rx[f.offset:f.offset+n])
	f.offset += n
	return n, nil
}

func (f *fakePort) Write(p []byte) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.writes = append(f.writes, p...)
	if f.writeAt.IsZero() {
		f.writeAt = time.Now()
	}
	switch {
	case len(f.queue) > 0:
		f.rx = append(f.rx, f.queue[0]...)
		f.queue = f.queue[1:]
	case f.resp != nil:
		f.rx = append(f.rx, f.resp...)
		f.resp = nil
	}
	return len(p), nil
}

// Flush 丢掉还没读走的字节，与真串口上的 PURGE_RXCLEAR 一致。
func (f *fakePort) Flush() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.flushes++
	f.rx = f.rx[:0]
	f.offset = 0
	return nil
}

func (f *fakePort) Close() error { return nil }

func (f *fakePort) sent() []byte {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]byte(nil), f.writes...)
}

func (f *fakePort) flushCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.flushes
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	clean := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		if s[i] != ' ' {
			clean = append(clean, s[i])
		}
	}
	b, err := hex.DecodeString(string(clean))
	if err != nil {
		t.Fatalf("测试用例里的十六进制写错了: %v", err)
	}
	return b
}
