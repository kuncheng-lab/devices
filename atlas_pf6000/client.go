package atlas_pf6000

import (
	"bufio"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
)

type Client struct {
	mu                                 sync.Mutex
	operationMu                        sync.Mutex
	conn                               net.Conn
	done                               chan struct{}
	connecting                         bool
	heartbeatActive                    bool
	commandWaiters                     map[string][]*commandWaiter
	psetSelectionSubscribed            bool
	selectedPset                       string
	psetChanged                        chan struct{}
	resultSubscribed                   bool
	multiSpindleResultSubscribed       bool
	multiSpindleResultSubscribePending bool
	resultSubscribePending             bool
	logf                               func(string, ...any)
	onResult                           func(TighteningResult)
}

func NewClient(logf func(string, ...any)) *Client {
	return &Client{
		logf:           logf,
		commandWaiters: make(map[string][]*commandWaiter),
		psetChanged:    make(chan struct{}),
	}
}

func (c *Client) Connect(host string) {
	go func() {
		if err := c.ConnectSession(host, DefaultPort, DefaultTimeoutMs); err != nil {
			c.log("PF6000 连接失败: %v", err)
			return
		}
	}()
}

func (c *Client) ConnectSession(host string, port int, timeoutMs int) error {
	c.mu.Lock()
	if c.conn != nil {
		c.mu.Unlock()
		return fmt.Errorf("PF6000 已连接，请先断开")
	}
	if c.connecting {
		c.mu.Unlock()
		return fmt.Errorf("PF6000 正在连接")
	}
	c.connecting = true
	c.mu.Unlock()
	defer func() {
		c.mu.Lock()
		c.connecting = false
		c.mu.Unlock()
	}()

	if port <= 0 {
		port = DefaultPort
	}
	if timeoutMs <= 0 {
		timeoutMs = DefaultTimeoutMs
	}

	conn, err := net.DialTimeout("tcp", net.JoinHostPort(host, strconv.Itoa(port)), time.Duration(timeoutMs)*time.Millisecond)
	if err != nil {
		return err
	}
	c.log("PF6000 TCP 连接成功，开始握手: %s:%d", host, port)

	reader := bufio.NewReader(conn)
	if err := c.handshake(conn, reader, timeoutMs); err != nil {
		_ = conn.Close()
		return err
	}

	c.mu.Lock()
	c.conn = conn
	c.done = make(chan struct{})
	c.resetProtocolStateLocked()
	c.mu.Unlock()

	c.log("PF6000 连接成功: %s:%d", host, port)
	go c.receiveLoop(conn, reader)
	c.StartHeartbeat()
	return nil
}

func (c *Client) Disconnect() {
	c.mu.Lock()
	done := c.done
	conn := c.conn
	if done != nil {
		close(done)
	}
	c.done = nil
	c.conn = nil
	c.heartbeatActive = false
	c.resetProtocolStateLocked()
	c.mu.Unlock()

	if conn != nil {
		_ = conn.Close()
		c.log("🔌 PF6000 已断开")
	}
}

func (c *Client) Connected() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.conn != nil
}

func (c *Client) SetTighteningResultHandler(handler func(TighteningResult)) {
	c.mu.Lock()
	c.onResult = handler
	c.mu.Unlock()
}

func (c *Client) handshake(conn net.Conn, reader *bufio.Reader, timeoutMs int) error {
	req := OpenProtocolProbeRequest{
		MID:       1,
		Revision:  1,
		TimeoutMs: timeoutMs,
	}
	normalizeProbeRequest(&req)
	frame, err := BuildOpenProtocolFrame(req)
	if err != nil {
		return err
	}

	deadline := time.Now().Add(time.Duration(req.TimeoutMs) * time.Millisecond)
	_ = conn.SetDeadline(deadline)
	if _, err := conn.Write(frame); err != nil {
		return fmt.Errorf("PF6000 握手发送失败: %w", err)
	}
	c.log("PF6000 TX: %s", FrameText(frame))

	rx, err := reader.ReadString(0)
	if err != nil {
		return fmt.Errorf("PF6000 握手无响应: %w", err)
	}
	raw := strings.TrimRight(rx, "\x00")
	msg, err := ParseOpenProtocolMessage(raw)
	c.log("------------------------------------")
	c.log("PF6000 RX: %s", VisibleFrame(raw))
	if err != nil {
		return fmt.Errorf("PF6000 握手响应解析失败: %w", err)
	}
	c.log("PF6000 解析: %s", SummarizeOpenProtocolResponse(msg))
	if msg.MID != "0002" {
		return fmt.Errorf("PF6000 握手返回 MID %s，期望 0002", msg.MID)
	}
	_ = conn.SetDeadline(time.Time{})
	return nil
}

func (c *Client) StartHeartbeat() {
	c.mu.Lock()
	if c.conn == nil || c.heartbeatActive {
		c.mu.Unlock()
		return
	}
	c.heartbeatActive = true
	c.mu.Unlock()
	go c.heartbeatLoop()
}

func (c *Client) SubscribeResults() {
	go func() {
		if err := c.EnsureResultSubscription(false, time.Duration(DefaultTimeoutMs)*time.Millisecond); err != nil {
			c.log("PF6000 订阅结果失败: %v", err)
		}
	}()
}

func (c *Client) SubscribeMultiSpindleResults() {
	go func() {
		if err := c.EnsureResultSubscription(true, time.Duration(DefaultTimeoutMs)*time.Millisecond); err != nil {
			c.log("PF6000 多轴结果订阅失败: %v", err)
		}
	}()
}

type ScanOptions struct {
	Host      string
	Port      int
	TimeoutMs int
	Limit     int
	OnStatus  func(string)
}

func (c *Client) ScanPrograms(opts ScanOptions) ([]PsetProgram, error) {
	limit := opts.Limit
	if limit <= 0 {
		limit = 1
	}
	if limit > 999 {
		limit = 999
	}
	timeoutMs := opts.TimeoutMs
	if timeoutMs <= 0 {
		timeoutMs = 800
	}
	if timeoutMs > 1200 {
		timeoutMs = 1200
	}
	port := opts.Port
	if port <= 0 {
		port = DefaultPort
	}

	c.log("开始探测程序(Pset): 001-%03d", limit)
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(opts.Host, strconv.Itoa(port)), 5*time.Second)
	if err != nil {
		return nil, fmt.Errorf("PF6000 临时连接失败: %w", err)
	}
	defer conn.Close()
	reader := bufio.NewReader(conn)
	handshake, _, err := c.scanOpenProtocolRequest(conn, reader, OpenProtocolProbeRequest{
		MID:       1,
		Revision:  1,
		TimeoutMs: timeoutMs,
	})
	if err != nil {
		return nil, fmt.Errorf("PF6000 探测握手失败: %w", err)
	}
	if handshake.MID != "0002" {
		return nil, fmt.Errorf("PF6000 探测握手返回 MID %s，已停止", handshake.MID)
	}

	programs := make([]PsetProgram, 0, limit)
	for id := 1; id <= limit; id++ {
		psetID := fmt.Sprintf("%03d", id)
		if opts.OnStatus != nil {
			opts.OnStatus(fmt.Sprintf("正在探测 %s/%03d", psetID, limit))
		}
		msg, _, err := c.scanOpenProtocolRequest(conn, reader, OpenProtocolProbeRequest{
			MID:       12,
			Revision:  1,
			Data:      psetID,
			TimeoutMs: timeoutMs,
		})
		if err != nil {
			c.log("程序 %s 探测失败: %v", psetID, err)
			continue
		}
		if msg.MID == "0004" {
			code := FieldOrUnknown(msg.Data, 4, 6)
			if code != "02" {
				c.log("程序 %s 不可读: 错误码 %s (%s)", psetID, code, OpenProtocolErrorText(code))
			}
			continue
		}
		program, ok := ParsePsetProgram(msg)
		if !ok {
			c.log("程序 %s 返回 MID %s，未作为 Pset 保存", psetID, msg.MID)
			continue
		}
		programs = append(programs, program)
		c.log("探测到程序 %s: %s，扭矩目标 %s，角度目标 %s", program.ID, emptyText(program.Name), emptyText(program.TorqueTarget), emptyText(program.AngleTarget))
		time.Sleep(50 * time.Millisecond)
	}
	return programs, nil
}

func (c *Client) Probe(req OpenProtocolProbeRequest) (OpenProtocolProbeResult, bool, error) {
	c.mu.Lock()
	conn := c.conn
	c.mu.Unlock()

	if conn != nil {
		return OpenProtocolProbeResult{}, true, c.sendPF6000Request(conn, req)
	}
	result, err := ProbeOpenProtocol(req)
	return result, false, err
}

func (c *Client) receiveLoop(conn net.Conn, reader *bufio.Reader) {
	for {
		c.mu.Lock()
		done := c.done
		c.mu.Unlock()

		select {
		case <-done:
			return
		default:
		}

		_ = conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		data, err := reader.ReadString(0)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			c.mu.Lock()
			if c.conn == conn {
				c.conn = nil
				if c.done == done {
					close(c.done)
					c.done = nil
				}
				c.heartbeatActive = false
				c.resetProtocolStateLocked()
			}
			c.mu.Unlock()
			_ = conn.Close()
			c.log("PF6000 连接断开")
			return
		}

		raw := strings.TrimRight(data, "\x00")
		msg, parseErr := ParseOpenProtocolMessage(raw)
		if parseErr == nil && msg.MID == "9999" {
			c.log("PF6000 收到心跳回应")
			continue
		}
		c.log("------------------------------------")
		c.log("PF6000 RX: %s", VisibleFrame(raw))
		if parseErr != nil {
			c.log("PF6000 解析失败: %v", parseErr)
		} else {
			c.log("PF6000 解析: %s", SummarizeOpenProtocolResponse(msg))
			c.handleCommandResponse(conn, msg)
			if msg.MID == "0015" {
				c.ackPF6000Message(conn, msg, 16)
				if psetID, ok := ParseSelectedPset(msg); ok {
					c.handleSelectedPset(conn, psetID)
				}
			}
			if msg.MID == "0061" {
				c.ackPF6000TighteningResult(conn, msg)
				if result, ok := ParseTighteningResult(msg); ok {
					c.handleTighteningResult(result)
				}
			}
			if msg.MID == "0101" {
				c.ackPF6000Message(conn, msg, 102)
				if results, ok := ParseMultiSpindleResult(msg); ok {
					for _, result := range results {
						c.handleTighteningResult(result)
					}
				}
			}
		}
	}
}

func (c *Client) handleTighteningResult(result TighteningResult) {
	c.mu.Lock()
	handler := c.onResult
	c.mu.Unlock()
	if handler != nil {
		handler(result)
	}
}

func (c *Client) handleCommandResponse(conn net.Conn, msg OpenProtocolMessage) {
	switch msg.MID {
	case "0005":
		acceptedMID := FieldOrUnknown(msg.Data, 0, 4)
		switch acceptedMID {
		case "0060":
			c.mu.Lock()
			if c.conn == conn {
				c.resultSubscribed = true
				c.resultSubscribePending = false
			}
			c.mu.Unlock()
			c.log("PF6000 订阅 0060 已确认，等待拧紧结果 MID 0061")
		case "0063":
			c.mu.Lock()
			if c.conn == conn {
				c.resultSubscribed = false
				c.resultSubscribePending = false
			}
			c.mu.Unlock()
			c.log("PF6000 已取消 MID 0060 结果订阅")
		case "0100":
			c.mu.Lock()
			if c.conn == conn {
				c.multiSpindleResultSubscribed = true
				c.multiSpindleResultSubscribePending = false
			}
			c.mu.Unlock()
			c.log("PF6000 多轴结果订阅 0100 已确认，等待 MID 0101")
		case "0014":
			c.mu.Lock()
			if c.conn == conn {
				c.psetSelectionSubscribed = true
			}
			c.mu.Unlock()
			c.log("PF6000 Pset 选择订阅 0014 已确认，等待 MID 0015")
		case "0018":
			c.log("PF6000 Pset 选择 0018 已确认")
		}
	case "0004":
		failedMID := FieldOrUnknown(msg.Data, 0, 4)
		code := FieldOrUnknown(msg.Data, 4, 6)
		switch failedMID {
		case "0060":
			c.handleSubscribeRejected(conn, code)
		case "0063":
			c.mu.Lock()
			if c.conn == conn {
				c.resultSubscribed = false
				c.resultSubscribePending = false
			}
			c.mu.Unlock()
			c.log("PF6000 取消旧订阅 0063 被拒绝，错误码 %s (%s)", code, OpenProtocolErrorText(code))
		case "0100":
			c.mu.Lock()
			if c.conn == conn {
				c.multiSpindleResultSubscribed = code == "33"
				c.multiSpindleResultSubscribePending = false
			}
			c.mu.Unlock()
			if code == "33" {
				c.log("PF6000 返回 0100/33: 多轴结果订阅已存在，继续等待 MID 0101")
			} else {
				c.log("PF6000 多轴结果订阅 0100 被拒绝，错误码 %s (%s)", code, OpenProtocolErrorText(code))
			}
		case "0014":
			c.mu.Lock()
			if c.conn == conn {
				c.psetSelectionSubscribed = code == "13"
			}
			c.mu.Unlock()
			c.log("PF6000 Pset 选择订阅 0014 被拒绝，错误码 %s (%s)", code, OpenProtocolErrorText(code))
		case "0018":
			c.log("PF6000 Pset 选择 0018 被拒绝，错误码 %s (%s)", code, OpenProtocolErrorText(code))
		}
	}
	c.dispatchCommandReply(conn, msg)
}

func (c *Client) handleSubscribeRejected(conn net.Conn, code string) {
	if code == "09" {
		c.mu.Lock()
		if c.conn == conn {
			c.resultSubscribed = true
			c.resultSubscribePending = false
		}
		c.mu.Unlock()
		c.log("PF6000 返回 0060/09: 控制器认为订阅已存在，继续等待 MID 0061；若仍无结果，请在调试页测试 0100 多轴结果订阅")
		return
	}
	c.mu.Lock()
	if c.conn == conn {
		c.resultSubscribed = false
		c.resultSubscribePending = false
	}
	c.mu.Unlock()
	c.log("PF6000 订阅 0060 被拒绝，错误码 %s (%s)，拧紧结果不会主动推送", code, OpenProtocolErrorText(code))
}

func (c *Client) heartbeatLoop() {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	heartbeat := []byte("002099990010    00  \x00")

	for {
		c.mu.Lock()
		done := c.done
		conn := c.conn
		active := c.heartbeatActive
		c.mu.Unlock()

		if !active {
			return
		}

		select {
		case <-done:
			return
		case <-ticker.C:
			c.mu.Lock()
			if c.conn == nil {
				c.mu.Unlock()
				return
			}
			_, err := conn.Write(heartbeat)
			c.mu.Unlock()
			if err != nil {
				c.log("PF6000 心跳发送失败: %v", err)
				c.Disconnect()
				return
			}
			c.log("PF6000 TX: %s", FrameText(heartbeat))
		}
	}
}

func (c *Client) ackPF6000TighteningResult(conn net.Conn, msg OpenProtocolMessage) {
	c.ackPF6000Message(conn, msg, 62)
}

func (c *Client) ackPF6000Message(conn net.Conn, msg OpenProtocolMessage, ackMID int) {
	err := c.sendPF6000Request(conn, OpenProtocolProbeRequest{
		MID:      ackMID,
		Revision: 1,
		Station:  openProtocolHeaderInt(msg.Station),
		Spindle:  openProtocolHeaderInt(msg.Spindle),
	})
	if err != nil {
		c.log("PF6000 %04d 确认发送失败: %v", ackMID, err)
		c.Disconnect()
		return
	}
	c.log("PF6000 已发送 MID %04d，确认收到 MID %s", ackMID, msg.MID)
}

func (c *Client) sendPF6000Request(conn net.Conn, req OpenProtocolProbeRequest) error {
	normalizeProbeRequest(&req)
	frame, err := BuildOpenProtocolFrame(req)
	if err != nil {
		c.log("PF6000 组帧失败: %v", err)
		return err
	}

	c.mu.Lock()
	_, err = conn.Write(frame)
	c.mu.Unlock()

	c.log("PF6000 TX: %s", FrameText(frame))
	if err != nil {
		c.log("PF6000 发送失败: %v", err)
	}
	return err
}

func (c *Client) scanOpenProtocolRequest(conn net.Conn, reader *bufio.Reader, req OpenProtocolProbeRequest) (OpenProtocolMessage, string, error) {
	normalizeProbeRequest(&req)
	frame, err := BuildOpenProtocolFrame(req)
	if err != nil {
		return OpenProtocolMessage{}, "", err
	}
	timeoutMs := req.TimeoutMs
	if timeoutMs <= 0 {
		timeoutMs = DefaultTimeoutMs
	}
	_ = conn.SetDeadline(time.Now().Add(time.Duration(timeoutMs) * time.Millisecond))
	if _, err := conn.Write(frame); err != nil {
		return OpenProtocolMessage{}, FrameText(frame), err
	}
	rx, err := reader.ReadString(0)
	if err != nil {
		return OpenProtocolMessage{}, FrameText(frame), err
	}
	raw := strings.TrimRight(rx, "\x00")
	msg, err := ParseOpenProtocolMessage(raw)
	if err != nil {
		return OpenProtocolMessage{}, VisibleFrame(raw), err
	}
	return msg, VisibleFrame(raw), nil
}

func normalizePsetText(text string) string {
	text = strings.TrimSpace(text)
	n, err := strconv.Atoi(text)
	if err != nil || n < 0 || n > 999 {
		if text == "" {
			return "001"
		}
		return text
	}
	return fmt.Sprintf("%03d", n)
}

func openProtocolHeaderInt(value string) int {
	n, _ := strconv.Atoi(strings.TrimSpace(value))
	return n
}

func (c *Client) log(format string, args ...any) {
	if c.logf != nil {
		c.logf(format, args...)
	}
}
