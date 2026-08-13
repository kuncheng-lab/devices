package melsec_plc_fx5u

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

type Client struct {
	mu       sync.Mutex
	host     string
	port     int
	timeout  time.Duration
	timer    uint16
	conn     net.Conn
	connMode protocolMode
	protocol protocolMode
	closed   bool
}

type protocolMode uint8

const (
	protocolUnknown protocolMode = iota
	protocolBinary
	protocolASCII
)

type Config struct {
	Host            string
	Port            int
	TimeoutMs       int
	MonitoringTimer uint16
}

func New(cfg Config) *Client {
	timeoutMs := cfg.TimeoutMs
	if timeoutMs <= 0 {
		timeoutMs = 2000
	}
	timer := cfg.MonitoringTimer
	if timer == 0 {
		timer = 16
	}
	return &Client{
		host:    cfg.Host,
		port:    cfg.Port,
		timeout: time.Duration(timeoutMs) * time.Millisecond,
		timer:   timer,
	}
}

func (p *Client) SetConfig(host string, port, timeoutMs int, timer uint16) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.closeConnectionLocked()
	p.host, p.port = host, port
	p.timeout = time.Duration(timeoutMs) * time.Millisecond
	p.timer = timer
	p.protocol = protocolUnknown
	p.closed = false
	if p.timeout <= 0 {
		p.timeout = 2 * time.Second
	}
	if p.timer == 0 {
		p.timer = 16
	}
}

// Close permanently closes the current PLC connection. SetConfig can be used
// to configure and reopen a Client after it has been closed.
func (p *Client) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.closed = true
	return p.closeConnectionLocked()
}

func (p *Client) TestConnection() error {
	_, err := p.ReadWord("D0")
	return err
}

func (p *Client) ReadWord(device string) (int16, error) {
	dev, err := parseDevice(device)
	if err != nil {
		return 0, err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if dev.bit {
		data, ascii, err := p.readDevice(dev, 1)
		if err != nil {
			return 0, err
		}
		if len(data) < 1 {
			return 0, fmt.Errorf("PLC FX5U bit read response too short")
		}
		if ascii {
			switch data[0] {
			case '1':
				return 1, nil
			case '0':
				return 0, nil
			default:
				return 0, fmt.Errorf("PLC FX5U ASCII bit read response invalid: %q", data[0])
			}
		}
		if data[0]&0x10 != 0 {
			return 1, nil
		}
		return 0, nil
	}
	data, ascii, err := p.readDevice(dev, 1)
	if err != nil {
		return 0, err
	}
	if ascii {
		if len(data) < 4 {
			return 0, fmt.Errorf("PLC FX5U ASCII word read response too short")
		}
		value, err := strconv.ParseUint(string(data[:4]), 16, 16)
		return int16(value), err
	}
	if len(data) < 2 {
		return 0, fmt.Errorf("PLC FX5U word read response too short")
	}
	return int16(binary.LittleEndian.Uint16(data[:2])), nil
}

func (p *Client) WriteWord(device string, value int16) error {
	dev, err := parseDevice(device)
	if err != nil {
		return err
	}
	if dev.bit {
		if value != 0 && value != 1 {
			return fmt.Errorf("bit device %s value must be 0 or 1", strings.ToUpper(strings.TrimSpace(device)))
		}
		p.mu.Lock()
		defer p.mu.Unlock()
		return p.writeBitDevice(dev, []bool{value != 0})
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.writeWordDevice(dev, []int16{value})
}

func (p *Client) readDevice(dev device, points uint16) ([]byte, bool, error) {
	if p.protocol == protocolASCII {
		asciiReq := buildASCIIRead(dev, p.timer, points)
		asciiData, err := p.sendASCII(asciiReq, true)
		return asciiData, true, err
	}

	req := buildBinaryRead(dev, p.timer, points)
	knownBinary := p.protocol == protocolBinary
	data, err := p.sendBinary(req, knownBinary)
	if err == nil {
		p.protocol = protocolBinary
		return data, false, nil
	}
	if knownBinary || !shouldTryASCII(err) {
		return nil, false, err
	}
	asciiReq := buildASCIIRead(dev, p.timer, points)
	asciiData, asciiErr := p.sendASCII(asciiReq, false)
	if asciiErr == nil {
		p.protocol = protocolASCII
		return asciiData, true, nil
	}
	return nil, false, fmt.Errorf("FX5U read failed in both 3E binary and 3E ASCII modes: binary: %v; ASCII: %v", err, asciiErr)
}

func (p *Client) writeBitDevice(dev device, values []bool) error {
	if p.protocol == protocolASCII {
		return p.writeASCIIBitDevice(dev, values, true)
	}

	req := buildBinaryBitWrite(dev, p.timer, values)
	knownBinary := p.protocol == protocolBinary
	if _, err := p.sendBinary(req, knownBinary); err != nil {
		if knownBinary || !shouldTryASCII(err) {
			return err
		}
		if asciiErr := p.writeASCIIBitDevice(dev, values, false); asciiErr != nil {
			return fmt.Errorf("FX5U bit write failed in both 3E binary and 3E ASCII modes: binary: %v; ASCII: %v", err, asciiErr)
		}
		p.protocol = protocolASCII
		return nil
	}
	p.protocol = protocolBinary
	return nil
}

func (p *Client) writeWordDevice(dev device, values []int16) error {
	if p.protocol == protocolASCII {
		return p.writeASCIIWordDevice(dev, values, true)
	}

	req := buildBinaryWordWrite(dev, p.timer, values)
	knownBinary := p.protocol == protocolBinary
	if _, err := p.sendBinary(req, knownBinary); err != nil {
		if knownBinary || !shouldTryASCII(err) {
			return err
		}
		if asciiErr := p.writeASCIIWordDevice(dev, values, false); asciiErr != nil {
			return fmt.Errorf("FX5U word write failed in both 3E binary and 3E ASCII modes: binary: %v; ASCII: %v", err, asciiErr)
		}
		p.protocol = protocolASCII
		return nil
	}
	p.protocol = protocolBinary
	return nil
}

func (p *Client) writeASCIIBitDevice(dev device, values []bool, reconnect bool) error {
	asciiReq := buildASCIIBitWrite(dev, p.timer, values)
	_, err := p.sendASCII(asciiReq, reconnect)
	return err
}

func (p *Client) writeASCIIWordDevice(dev device, values []int16, reconnect bool) error {
	asciiReq := buildASCIIWordWrite(dev, p.timer, values)
	_, err := p.sendASCII(asciiReq, reconnect)
	return err
}

// sendBinary executes a transaction on the persistent binary connection.
// Once binary mode has been confirmed, a transport failure is retried once on
// a fresh connection. ReadWord and WriteWord are idempotent, so repeating the
// exact operation is safe if a response was lost after the PLC handled it.
func (p *Client) sendBinary(req []byte, reconnect bool) ([]byte, error) {
	attempts := 1
	if reconnect {
		attempts = 2
	}
	var lastErr error
	for attempt := 0; attempt < attempts; attempt++ {
		c, err := p.connectionLocked(protocolBinary)
		if err != nil {
			lastErr = err
			continue
		}
		addr := p.addrLocked()
		if err := c.SetDeadline(time.Now().Add(p.timeout)); err != nil {
			lastErr = fmt.Errorf("FX5U %s set deadline failed: %w", addr, err)
			p.closeConnectionLocked()
			continue
		}
		if err := writeAll(c, req); err != nil {
			lastErr = fmt.Errorf("FX5U %s TX % X write failed: %w", addr, req, err)
			p.closeConnectionLocked()
			continue
		}
		resp, err := readBinaryResponse(c)
		if err != nil {
			lastErr = fmt.Errorf("FX5U %s TX % X read response failed: %w", addr, req, describeNetError(err))
			p.closeConnectionLocked()
			continue
		}
		data, err := validateBinaryResponse(resp)
		if err != nil {
			p.closeConnectionLocked()
			return nil, fmt.Errorf("FX5U %s TX % X RX % X: %w", addr, req, resp, err)
		}
		return data, nil
	}
	return nil, lastErr
}

func (p *Client) sendASCII(req string, reconnect bool) ([]byte, error) {
	attempts := 1
	if reconnect {
		attempts = 2
	}
	var lastErr error
	for attempt := 0; attempt < attempts; attempt++ {
		c, err := p.connectionLocked(protocolASCII)
		if err != nil {
			lastErr = err
			continue
		}
		addr := p.addrLocked()
		if err := c.SetDeadline(time.Now().Add(p.timeout)); err != nil {
			lastErr = fmt.Errorf("FX5U %s set deadline failed: %w", addr, err)
			p.closeConnectionLocked()
			continue
		}
		if err := writeAll(c, []byte(req)); err != nil {
			lastErr = fmt.Errorf("FX5U %s TX ASCII %s write failed: %w", addr, req, err)
			p.closeConnectionLocked()
			continue
		}
		resp, err := readASCIIResponse(c)
		if err != nil {
			lastErr = fmt.Errorf("FX5U %s TX ASCII %s read response failed: %w", addr, req, describeNetError(err))
			p.closeConnectionLocked()
			continue
		}
		data, err := validateASCIIResponse(resp)
		if err != nil {
			p.closeConnectionLocked()
			return nil, fmt.Errorf("FX5U %s TX ASCII %s RX ASCII %s: %w", addr, req, string(resp), err)
		}
		return data, nil
	}
	return nil, lastErr
}

func (p *Client) connectionLocked(mode protocolMode) (net.Conn, error) {
	if p.closed {
		return nil, fmt.Errorf("FX5U client is closed")
	}
	if p.conn != nil && p.connMode == mode {
		return p.conn, nil
	}
	p.closeConnectionLocked()
	c, err := net.DialTimeout("tcp", p.addrLocked(), p.timeout)
	if err != nil {
		return nil, err
	}
	p.conn = c
	p.connMode = mode
	return c, nil
}

func (p *Client) closeConnectionLocked() error {
	if p.conn == nil {
		p.connMode = protocolUnknown
		return nil
	}
	c := p.conn
	p.conn = nil
	p.connMode = protocolUnknown
	return c.Close()
}

func (p *Client) addrLocked() string {
	return net.JoinHostPort(p.host, strconv.Itoa(p.port))
}

func writeAll(c net.Conn, data []byte) error {
	for len(data) > 0 {
		n, err := c.Write(data)
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

func readBinaryResponse(c net.Conn) ([]byte, error) {
	header := make([]byte, 9)
	if _, err := io.ReadFull(c, header); err != nil {
		return nil, err
	}
	bodyLen := int(binary.LittleEndian.Uint16(header[7:9]))
	if bodyLen <= 0 {
		return header, nil
	}
	body := make([]byte, bodyLen)
	if _, err := io.ReadFull(c, body); err != nil {
		return nil, err
	}
	return append(header, body...), nil
}

func readASCIIResponse(c net.Conn) ([]byte, error) {
	header := make([]byte, 18)
	if _, err := io.ReadFull(c, header); err != nil {
		return nil, err
	}
	bodyLen, err := strconv.ParseUint(string(header[14:18]), 16, 16)
	if err != nil {
		return nil, fmt.Errorf("PLC FX5U ASCII response length invalid: %w", err)
	}
	if bodyLen == 0 {
		return header, nil
	}
	body := make([]byte, bodyLen)
	if _, err := io.ReadFull(c, body); err != nil {
		return nil, err
	}
	return append(header, body...), nil
}

type device struct {
	address uint32
	code    byte
	ascii   string
	base    int
	bit     bool
}

func parseDevice(text string) (device, error) {
	text = strings.ToUpper(strings.TrimSpace(text))
	if len(text) < 2 {
		return device{}, fmt.Errorf("invalid FX5U device %q", text)
	}
	prefix, addrText := text[:1], text[1:]
	dev := device{base: 10}
	switch prefix {
	case "M":
		dev.code, dev.ascii, dev.bit = 0x90, "M*", true
	case "X":
		dev.code, dev.ascii, dev.base, dev.bit = 0x9C, "X*", 16, true
	case "Y":
		dev.code, dev.ascii, dev.base, dev.bit = 0x9D, "Y*", 16, true
	case "B":
		dev.code, dev.ascii, dev.base, dev.bit = 0xA0, "B*", 16, true
	case "D":
		dev.code, dev.ascii = 0xA8, "D*"
	case "R":
		dev.code, dev.ascii = 0xAF, "R*"
	case "W":
		dev.code, dev.ascii, dev.base = 0xB4, "W*", 16
	default:
		return dev, fmt.Errorf("unsupported FX5U device %q", prefix)
	}
	addr, err := strconv.ParseUint(addrText, dev.base, 24)
	dev.address = uint32(addr)
	return dev, err
}

func buildBinaryRead(dev device, timer uint16, points uint16) []byte {
	req := newBinaryRequest(timer, 12)
	binary.LittleEndian.PutUint16(req[11:], 0x0401)
	binary.LittleEndian.PutUint16(req[13:], subcommand(dev))
	putDevice(req[15:], dev)
	binary.LittleEndian.PutUint16(req[19:], points)
	return req
}

func buildASCIIRead(dev device, timer uint16, points uint16) string {
	body := fmt.Sprintf("%04X0401%04X%s%s%04X", timer, subcommand(dev), dev.ascii, asciiDeviceAddress(dev), points)
	return newASCIIRequest(body)
}

func buildBinaryBitWrite(dev device, timer uint16, values []bool) []byte {
	dataLen := (len(values) + 1) / 2
	req := newBinaryRequest(timer, 12+dataLen)
	binary.LittleEndian.PutUint16(req[11:], 0x1401)
	binary.LittleEndian.PutUint16(req[13:], subcommand(dev))
	putDevice(req[15:], dev)
	binary.LittleEndian.PutUint16(req[19:], uint16(len(values)))
	for i, value := range values {
		if !value {
			continue
		}
		if i%2 == 0 {
			req[21+i/2] |= 0x10
		} else {
			req[21+i/2] |= 0x01
		}
	}
	return req
}

func buildASCIIBitWrite(dev device, timer uint16, values []bool) string {
	var data strings.Builder
	for _, value := range values {
		if value {
			data.WriteByte('1')
		} else {
			data.WriteByte('0')
		}
	}
	body := fmt.Sprintf("%04X1401%04X%s%s%04X%s", timer, subcommand(dev), dev.ascii, asciiDeviceAddress(dev), len(values), data.String())
	return newASCIIRequest(body)
}

func buildBinaryWordWrite(dev device, timer uint16, values []int16) []byte {
	req := newBinaryRequest(timer, 12+len(values)*2)
	binary.LittleEndian.PutUint16(req[11:], 0x1401)
	binary.LittleEndian.PutUint16(req[13:], subcommand(dev))
	putDevice(req[15:], dev)
	binary.LittleEndian.PutUint16(req[19:], uint16(len(values)))
	for i, value := range values {
		binary.LittleEndian.PutUint16(req[21+i*2:], uint16(value))
	}
	return req
}

func buildASCIIWordWrite(dev device, timer uint16, values []int16) string {
	var data strings.Builder
	for _, value := range values {
		fmt.Fprintf(&data, "%04X", uint16(value))
	}
	body := fmt.Sprintf("%04X1401%04X%s%s%04X%s", timer, subcommand(dev), dev.ascii, asciiDeviceAddress(dev), len(values), data.String())
	return newASCIIRequest(body)
}

func newBinaryRequest(timer uint16, requestDataLen int) []byte {
	req := make([]byte, 9+requestDataLen)
	req[0], req[1] = 0x50, 0x00
	req[2] = 0x00
	req[3] = 0xFF
	binary.LittleEndian.PutUint16(req[4:], 0x03FF)
	req[6] = 0x00
	binary.LittleEndian.PutUint16(req[7:], uint16(requestDataLen))
	binary.LittleEndian.PutUint16(req[9:], timer)
	return req
}

func newASCIIRequest(body string) string {
	return fmt.Sprintf("500000FF03FF00%04X%s", len(body), body)
}

func putDevice(dst []byte, dev device) {
	dst[0] = byte(dev.address)
	dst[1] = byte(dev.address >> 8)
	dst[2] = byte(dev.address >> 16)
	dst[3] = dev.code
}

func asciiDeviceAddress(dev device) string {
	if dev.base == 16 {
		return fmt.Sprintf("%06X", dev.address)
	}
	return fmt.Sprintf("%06d", dev.address)
}

func subcommand(dev device) uint16 {
	if dev.bit {
		return 0x0001
	}
	return 0x0000
}

func validateBinaryResponse(resp []byte) ([]byte, error) {
	if len(resp) < 11 {
		return nil, fmt.Errorf("PLC FX5U response too short")
	}
	if resp[0] != 0xD0 || resp[1] != 0x00 {
		return nil, fmt.Errorf("PLC FX5U response subheader 0x%02X%02X", resp[0], resp[1])
	}
	endCode := binary.LittleEndian.Uint16(resp[9:11])
	if endCode != 0 {
		return nil, fmt.Errorf("PLC FX5U completion code 0x%04X", endCode)
	}
	return resp[11:], nil
}

func validateASCIIResponse(resp []byte) ([]byte, error) {
	if len(resp) < 22 {
		return nil, fmt.Errorf("PLC FX5U ASCII response too short")
	}
	if !strings.EqualFold(string(resp[:4]), "D000") {
		return nil, fmt.Errorf("PLC FX5U ASCII response subheader %q", string(resp[:4]))
	}
	bodyLen, err := strconv.ParseUint(string(resp[14:18]), 16, 16)
	if err != nil {
		return nil, fmt.Errorf("PLC FX5U ASCII response length invalid: %w", err)
	}
	if len(resp) != 18+int(bodyLen) {
		return nil, fmt.Errorf("PLC FX5U ASCII response length = %d, want %d", len(resp), 18+int(bodyLen))
	}
	endCode, err := strconv.ParseUint(string(resp[18:22]), 16, 16)
	if err != nil {
		return nil, fmt.Errorf("PLC FX5U ASCII completion code invalid: %w", err)
	}
	if endCode != 0 {
		return nil, fmt.Errorf("PLC FX5U ASCII completion code 0x%04X", endCode)
	}
	return resp[22:], nil
}

func shouldTryASCII(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "read response failed") ||
		strings.Contains(msg, "response subheader") ||
		strings.Contains(msg, "response too short")
}

func describeNetError(err error) error {
	if err == nil {
		return nil
	}
	if os.IsTimeout(err) {
		return fmt.Errorf("timeout waiting for PLC response: %w", err)
	}
	if err == io.EOF {
		return fmt.Errorf("PLC closed connection without response: %w", err)
	}
	return err
}
