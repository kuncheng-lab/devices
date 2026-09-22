package modbus_tcp

import (
	"encoding/hex"
	"errors"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

// 测试向量取自**真实设备**（LTC 智枢磁浮控制器，192.168.3.30:502）：
// 读 A600~A618 这一帧的请求与应答是现场抓到的原文，改一个字节都过不了。
//
// 应答按寄存器拆开写，便于核对：数据段 25 个寄存器 = 50 字节。
var realMaglevData = []uint16{
	0x0002,                 // A600 系统状态 = 2 悬浮
	0x0000, 0x0000, 0x0000, // A601~A603 故障码组与详情
	0x0000, 0x0000, 0x0000, 0x0000, // A604~A607 保留
	0x00C8,                 // A608 功率母线电压 = 200
	0x0000,                 // A609 保留
	0x0000, 0x0000, 0x0000, // A60A~A60C 位移（停机，全 0）
	0x0000,                                         // A60D 转子伸缩量
	0x0024, 0x0030, 0x0031, 0x0030, 0x001B, 0x001C, // A60E~A613 轴承温度 1~6
	0x001C, 0x001C, 0x001C, 0x001C, // A614~A617 电机温度 1~4
	0x07D0, // A618 转速 = 2000
}

func realMaglevResponse() string {
	b := "000100000035050332" // MBAP + 单元号 + 功能码 + 字节数(0x32=50)
	for _, v := range realMaglevData {
		b += hex.EncodeToString([]byte{byte(v >> 8), byte(v)})
	}
	return b
}

func TestReadRegistersParsesRealDeviceFrame(t *testing.T) {
	// 请求：事务号 1、协议 0、长度 6、单元号 5、03 读 A600 起 25 个
	req := "0001000000060503a6000019"

	srv := newFakeServer(t, realMaglevResponse())
	c := New(Config{Host: srv.addr(), UnitID: 5, ResponseTimeoutMS: 500})
	defer c.Close()

	regs, err := c.ReadHoldingRegisters(0, 0xA600, 25)
	if err != nil {
		t.Fatalf("读取失败: %v", err)
	}
	if len(regs) != 25 {
		t.Fatalf("寄存器个数 期望 25 实际 %d", len(regs))
	}
	for i, want := range realMaglevData {
		if regs[i] != want {
			t.Errorf("第 %d 个寄存器 期望 0x%04X 实际 0x%04X", i, want, regs[i])
		}
	}
	// 逐字节核对发出去的帧（MBAP 组装正确）
	if got := srv.received(); got != req {
		t.Fatalf("请求帧不符\n期望 %s\n实际 %s", req, got)
	}
}

// TCP 是字节流：服务端把一个应答拆成几个小包发，也必须能收全。
// 这是这类客户端最常见的 bug —— 只 Read 一次就解析，会偶发读错寄存器。
func TestReadRegistersHandlesSplitResponse(t *testing.T) {
	resp := "0001000000050503020002" // 读 1 个寄存器，值 2
	srv := newFakeServerSplit(t, resp, 3)
	c := New(Config{Host: srv.addr(), UnitID: 5, ResponseTimeoutMS: 500})
	defer c.Close()

	regs, err := c.ReadHoldingRegisters(0, 0xA600, 1)
	if err != nil {
		t.Fatalf("读取失败: %v", err)
	}
	if len(regs) != 1 || regs[0] != 2 {
		t.Fatalf("寄存器内容不对 %v", regs)
	}
}

// 单元号：请求里填什么，MBAP 第 7 字节就该是什么；填 0 时用配置里的。
func TestUnitIDFallsBackToConfig(t *testing.T) {
	srv := newFakeServer(t, "0001000000050503020002")
	c := New(Config{Host: srv.addr(), UnitID: 5, ResponseTimeoutMS: 500})
	defer c.Close()

	if _, err := c.ReadHoldingRegisters(0, 0xA600, 1); err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(srv.received(), "0503a6000001") {
		t.Fatalf("单元号应当取配置里的 5，实际帧 %s", srv.received())
	}
}

func TestReadRegistersRejectsException(t *testing.T) {
	// 异常应答：功能码 0x83、异常码 11（AC320 手册：读取参数字节数有误）
	srv := newFakeServer(t, "00010000000305830B")
	c := New(Config{Host: srv.addr(), UnitID: 5, ResponseTimeoutMS: 500})
	defer c.Close()

	_, err := c.ReadHoldingRegisters(0, 0xA600, 1)
	var ex *ExceptionError
	if !errors.As(err, &ex) {
		t.Fatalf("期望 ExceptionError 实际 %v", err)
	}
	if ex.Code != 0x0B {
		t.Fatalf("异常码期望 11 实际 %d", ex.Code)
	}
}

func TestReadRegistersRejectsMismatchedTransaction(t *testing.T) {
	// 应答的事务号是 99，我们发的是 1 —— 这条连接上有多余数据，不能认
	srv := newFakeServerRaw(t, "0063000000050503020002")
	c := New(Config{Host: srv.addr(), UnitID: 5, ResponseTimeoutMS: 500})
	defer c.Close()

	if _, err := c.ReadHoldingRegisters(0, 0xA600, 1); err == nil {
		t.Fatal("事务号不符却读成功了")
	}
}

func TestReadRegistersTimeout(t *testing.T) {
	// 服务端连上但不回任何东西
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			_ = conn // 拿着连接不说话
		}
	}()

	c := New(Config{Host: ln.Addr().String(), UnitID: 1, ResponseTimeoutMS: 300})
	defer c.Close()

	start := time.Now()
	if _, err := c.ReadHoldingRegisters(0, 0, 1); !errors.Is(err, ErrTimeout) {
		t.Fatalf("期望超时 实际 %v", err)
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Fatalf("超时应当按配置的 300ms 左右返回，实际用了 %s", d)
	}
}

func TestReadRegistersRejectsBadCount(t *testing.T) {
	c := New(Config{Host: "127.0.0.1:502"})
	defer c.Close()
	for _, n := range []uint16{0, 126} {
		if _, err := c.ReadHoldingRegisters(0, 0, n); err == nil {
			t.Fatalf("count=%d 应被拒绝", n)
		}
	}
}

func TestUnconfiguredHostIsRejected(t *testing.T) {
	c := New(Config{})
	defer c.Close()
	if _, err := c.ReadHoldingRegisters(0, 0, 1); err == nil {
		t.Fatal("没配主机地址却读成功了")
	}
}

// 连接坏掉之后下一次调用要自动重连，不能一直用一条死连接。
func TestReconnectsAfterServerCloses(t *testing.T) {
	resp := "0001000000050503020002"
	srv := newFakeServerCloseAfter(t, resp, 1)

	c := New(Config{Host: srv.addr(), UnitID: 5, ResponseTimeoutMS: 500})
	defer c.Close()

	if _, err := c.ReadHoldingRegisters(0, 0xA600, 1); err != nil {
		t.Fatalf("第一次读失败: %v", err)
	}
	// 服务端这时候把连接关了；第二次读会先撞上失败，然后重连
	time.Sleep(100 * time.Millisecond)
	_, err := c.ReadHoldingRegisters(0, 0xA600, 1)
	if err != nil {
		// 允许这一次失败（连的是刚关掉的旧连接），但连接必须被丢掉
		if _, err2 := c.ReadHoldingRegisters(0, 0xA600, 1); err2 != nil {
			t.Fatalf("重连后仍然读不到: %v / %v", err, err2)
		}
	}
}

// ---- 测试替身 --------------------------------------------------------------

// fakeServer 是最小的 Modbus TCP 服务端：收到了就往回吐预置的应答。
type fakeServer struct {
	t        *testing.T
	ln       net.Listener
	mu       sync.Mutex
	last     []byte
	reply    []byte
	split    int  // >0 时把应答拆成这么多个包发
	closeNth int  // >0 时在第 N 次请求后关掉连接
	raw      bool // true 时不改写应答里的事务号（测不匹配用）
	count    int
}

func newFakeServer(t *testing.T, respHex string) *fakeServer {
	t.Helper()
	return newFakeServerSplit(t, respHex, 0)
}

// newFakeServerRaw 原样回预置的应答、不改写事务号 —— 用来构造"事务号不符"的场景。
func newFakeServerRaw(t *testing.T, respHex string) *fakeServer {
	s := newFakeServer(t, respHex)
	s.mu.Lock()
	s.raw = true
	s.mu.Unlock()
	return s
}

func newFakeServerSplit(t *testing.T, respHex string, split int) *fakeServer {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := &fakeServer{t: t, ln: ln, split: split}
	if respHex != "" {
		s.reply, _ = hex.DecodeString(respHex)
	}
	t.Cleanup(func() { ln.Close() })
	go s.serve()
	return s
}

func newFakeServerCloseAfter(t *testing.T, respHex string, nth int) *fakeServer {
	s := newFakeServer(t, respHex)
	s.mu.Lock()
	s.closeNth = nth
	s.mu.Unlock()
	return s
}

func (s *fakeServer) addr() string { return s.ln.Addr().String() }

func (s *fakeServer) received() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return hex.EncodeToString(s.last)
}

func (s *fakeServer) serve() {
	for {
		conn, err := s.ln.Accept()
		if err != nil {
			return
		}
		go s.handle(conn)
	}
}

func (s *fakeServer) handle(conn net.Conn) {
	defer conn.Close()
	for {
		buf := make([]byte, 512)
		n, err := conn.Read(buf)
		if n > 0 {
			req := buf[:n]
			s.mu.Lock()
			s.last = append([]byte(nil), req...)
			s.count++
			nth := s.closeNth
			reply := append([]byte(nil), s.reply...)
			split := s.split
			raw := s.raw
			s.mu.Unlock()

			if reply != nil {
				// 把应答里的事务号改成请求的（真实设备就是这么回的）；
				// raw 模式不改写，用来伪造"事务号不符"的异常应答
				if !raw && len(reply) >= 2 && len(req) >= 2 {
					reply[0], reply[1] = req[0], req[1]
				}
				if split > 0 && len(reply) > split {
					for i := 0; i < len(reply); i += split {
						end := i + split
						if end > len(reply) {
							end = len(reply)
						}
						if _, err := conn.Write(reply[i:end]); err != nil {
							return
						}
						time.Sleep(5 * time.Millisecond)
					}
				} else if _, err := conn.Write(reply); err != nil {
					return
				}
			}
			if nth > 0 && s.countNow() >= nth {
				return // 关掉连接，测重连
			}
		}
		if err != nil {
			return
		}
	}
}

func (s *fakeServer) countNow() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.count
}

// 连接空闲超过超时时间之后，下一次请求必须还能成功。
//
// Go 的 deadline 是绝对时刻：如果在建立连接时设一次 SetDeadline(now+超时)，
// 那么连接空闲超过那个时长之后，下一次 Write 会立刻超时失败 ——
// 表现为"每 N 秒必失败一次"这种极有规律的假故障（现场实测踩到过：
// 轮询 400ms、超时 2 秒，正好每 5 次挂 1 次）。deadline 必须每次交易重设。
func TestIdleConnectionStillWorksAfterTimeoutWindow(t *testing.T) {
	resp := "0001000000050503020002"
	srv := newFakeServer(t, resp)
	// 超时给 300ms，但两次请求之间空闲 700ms（远超它）
	c := New(Config{Host: srv.addr(), UnitID: 5, ResponseTimeoutMS: 300})
	defer c.Close()

	if _, err := c.ReadHoldingRegisters(0, 0xA600, 1); err != nil {
		t.Fatalf("第一次读失败: %v", err)
	}
	time.Sleep(700 * time.Millisecond) // 空闲超过超时窗口
	if _, err := c.ReadHoldingRegisters(0, 0xA600, 1); err != nil {
		t.Fatalf("空闲 %s 后应当能继续读，实际: %v", 700*time.Millisecond, err)
	}
	time.Sleep(700 * time.Millisecond)
	if _, err := c.ReadHoldingRegisters(0, 0xA600, 1); err != nil {
		t.Fatalf("第二次空闲后仍应当能读，实际: %v", err)
	}
}

// 反复请求不能出现"规律性失败"（旧 bug 的表现）。
func TestRepeatedRequestsNoPeriodicFailure(t *testing.T) {
	resp := "0001000000050503020002"
	srv := newFakeServer(t, resp)
	c := New(Config{Host: srv.addr(), UnitID: 5, ResponseTimeoutMS: 200})
	defer c.Close()

	const n = 12
	for i := 1; i <= n; i++ {
		if _, err := c.ReadHoldingRegisters(0, 0xA600, 1); err != nil {
			t.Fatalf("第 %d 次读失败: %v", i, err)
		}
		time.Sleep(250 * time.Millisecond) // 比超时略长
	}
}
