package melsec_plc_fx3u

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
)

type Client struct {
	mu      sync.Mutex
	host    string
	port    int
	timeout time.Duration
	timer   uint16
	conn    net.Conn
}

type Config struct {
	Host            string
	Port            int
	TimeoutMs       int
	MonitoringTimer uint16
}

func New(cfg Config) *Client {
	return &Client{
		host:    cfg.Host,
		port:    cfg.Port,
		timeout: time.Duration(cfg.TimeoutMs) * time.Millisecond,
		timer:   cfg.MonitoringTimer,
	}
}

func (p *Client) SetConfig(host string, port, timeoutMs int, timer uint16) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.closeLocked()
	p.host, p.port = host, port
	p.timeout = time.Duration(timeoutMs) * time.Millisecond
	p.timer = timer
}

// Close closes the persistent TCP connection. The next operation reconnects.
func (p *Client) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.closeLocked()
}

func (p *Client) TestConnection() error {
	_, err := p.ReadWord("D0")
	return err
}

func (p *Client) OpenGate() error  { return p.WriteWord("D0", 1) }
func (p *Client) CloseGate() error { return p.WriteWord("D0", 0) }

func (p *Client) ReadWord(device string) (int16, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	dev, err := parseDevice(device)
	if err != nil {
		return 0, err
	}
	if resp, err := p.sendLocked(buildBinaryRead(dev, p.timer, 1)); err == nil {
		if len(resp) < 4 {
			return 0, fmt.Errorf("PLC binary read response too short")
		}
		if err := validateBinary(resp, 0x81); err == nil {
			return int16(binary.LittleEndian.Uint16(resp[2:4])), nil
		}
	}
	p.closeLocked()
	resp, err := p.sendASCIILocked(buildASCIIRead(dev, p.timer, 1))
	if err != nil {
		return 0, err
	}
	if err := validateASCII(resp, "81"); err != nil {
		return 0, err
	}
	v, err := strconv.ParseUint(resp[4:8], 16, 16)
	return int16(v), err
}

func (p *Client) WriteWord(device string, value int16) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	dev, err := parseDevice(device)
	if err != nil {
		return err
	}
	if resp, err := p.sendLocked(buildBinaryWrite(dev, p.timer, []int16{value})); err == nil {
		if len(resp) >= 2 && validateBinary(resp, 0x83) == nil {
			return nil
		}
	}
	p.closeLocked()
	resp, err := p.sendASCIILocked(buildASCIIWrite(dev, p.timer, []int16{value}))
	if err != nil {
		return err
	}
	return validateASCII(resp, "83")
}

func (p *Client) sendLocked(req []byte) ([]byte, error) {
	var lastErr error
	for attempt := 0; attempt < 2; attempt++ {
		if err := p.connectLocked(); err != nil {
			lastErr = err
			continue
		}
		_ = p.conn.SetDeadline(time.Now().Add(p.timeout))
		if err := writeAll(p.conn, req); err == nil {
			if resp, readErr := readPLC(p.conn); readErr == nil {
				return resp, nil
			} else {
				lastErr = readErr
			}
		} else {
			lastErr = err
		}
		p.closeLocked()
	}
	return nil, fmt.Errorf("PLC transaction failed after reconnect: %w", lastErr)
}

func (p *Client) sendASCIILocked(req string) (string, error) {
	resp, err := p.sendLocked([]byte(req))
	if err != nil {
		return "", err
	}
	return strings.TrimRight(string(resp), "\x00\r\n "), nil
}

func (p *Client) connectLocked() error {
	if p.conn != nil {
		return nil
	}
	c, err := net.DialTimeout("tcp", p.addr(), p.timeout)
	if err != nil {
		return err
	}
	if tcp, ok := c.(*net.TCPConn); ok {
		_ = tcp.SetNoDelay(true)
		_ = tcp.SetKeepAlive(true)
		_ = tcp.SetKeepAlivePeriod(30 * time.Second)
	}
	p.conn = c
	return nil
}

func (p *Client) closeLocked() error {
	if p.conn == nil {
		return nil
	}
	err := p.conn.Close()
	p.conn = nil
	return err
}

func writeAll(w io.Writer, data []byte) error {
	for len(data) > 0 {
		n, err := w.Write(data)
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrUnexpectedEOF
		}
		data = data[n:]
	}
	return nil
}

func (p *Client) addr() string {
	return net.JoinHostPort(p.host, strconv.Itoa(p.port))
}

func readPLC(c net.Conn) ([]byte, error) {
	buf := make([]byte, 256)
	n, err := c.Read(buf)
	if err != nil {
		return nil, err
	}
	total := n
	for {
		_ = c.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
		n, err = c.Read(buf[total:])
		if n > 0 {
			total += n
		}
		if err != nil || total == len(buf) {
			break
		}
	}
	return buf[:total], nil
}

type device struct {
	address uint32
	low     byte
	high    byte
	ascii   string
}

func parseDevice(text string) (device, error) {
	text = strings.ToUpper(strings.TrimSpace(text))
	if len(text) < 2 {
		return device{}, fmt.Errorf("invalid MELSEC device %q", text)
	}
	prefix, addrText := text[:1], text[1:]
	var dev device
	var base int
	switch prefix {
	case "D":
		dev, base = device{low: 0x20, high: 0x44, ascii: "4420"}, 10
	case "R":
		dev, base = device{low: 0x20, high: 0x52, ascii: "5220"}, 10
	case "W":
		dev, base = device{low: 0x20, high: 0x57, ascii: "5720"}, 16
	case "X":
		dev, base = device{low: 0x20, high: 0x58, ascii: "5820"}, 8
	case "Y":
		dev, base = device{low: 0x20, high: 0x59, ascii: "5920"}, 8
	case "M":
		dev, base = device{low: 0x20, high: 0x4D, ascii: "4D20"}, 10
	default:
		return dev, fmt.Errorf("unsupported MELSEC device %q", prefix)
	}
	addr, err := strconv.ParseUint(addrText, base, 32)
	dev.address = uint32(addr)
	return dev, err
}

func buildBinaryRead(dev device, timer, points uint16) []byte {
	req := make([]byte, 12)
	req[0], req[1] = 0x01, 0xFF
	binary.LittleEndian.PutUint16(req[2:], timer)
	binary.LittleEndian.PutUint32(req[4:], dev.address)
	req[8], req[9] = dev.low, dev.high
	binary.LittleEndian.PutUint16(req[10:], points)
	return req
}

func buildBinaryWrite(dev device, timer uint16, values []int16) []byte {
	req := make([]byte, 12+len(values)*2)
	req[0], req[1] = 0x03, 0xFF
	binary.LittleEndian.PutUint16(req[2:], timer)
	binary.LittleEndian.PutUint32(req[4:], dev.address)
	req[8], req[9] = dev.low, dev.high
	binary.LittleEndian.PutUint16(req[10:], uint16(len(values)))
	for i, v := range values {
		binary.LittleEndian.PutUint16(req[12+i*2:], uint16(v))
	}
	return req
}

func buildASCIIRead(dev device, timer, points uint16) string {
	return fmt.Sprintf("01FF%04X%s%08X%02X%02X", timer, dev.ascii, dev.address, byte(points), byte(points>>8))
}

func buildASCIIWrite(dev device, timer uint16, values []int16) string {
	var b strings.Builder
	fmt.Fprintf(&b, "03FF%04X%s%08X%02X%02X", timer, dev.ascii, dev.address, byte(len(values)), byte(len(values)>>8))
	for _, v := range values {
		fmt.Fprintf(&b, "%04X", uint16(v))
	}
	return b.String()
}

func validateBinary(resp []byte, sub byte) error {
	if len(resp) < 2 {
		return fmt.Errorf("PLC binary response too short")
	}
	if resp[0] == 0x5B {
		return fmt.Errorf("PLC abnormal response 0x%02X", resp[1])
	}
	if resp[0] != sub || resp[1] != 0 {
		return fmt.Errorf("PLC completion code 0x%02X%02X", resp[0], resp[1])
	}
	return nil
}

func validateASCII(resp, sub string) error {
	if len(resp) < 4 {
		return fmt.Errorf("PLC ASCII response too short")
	}
	if _, err := hex.DecodeString(resp[:4]); err != nil {
		return fmt.Errorf("PLC ASCII response invalid: %w", err)
	}
	if strings.EqualFold(resp[:2], "5B") {
		return fmt.Errorf("PLC abnormal response %s", resp[2:4])
	}
	if !strings.EqualFold(resp[:2], sub) || resp[2:4] != "00" {
		return fmt.Errorf("PLC completion code %s", resp[:4])
	}
	return nil
}
