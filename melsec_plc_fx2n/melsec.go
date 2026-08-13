// Package melsec_plc_fx2n implements the Mitsubishi FX programming-port
// protocol used by FX2N PLCs, including the FX2N-32MT.
//
// It talks to a serial programming cable such as SC-09/USB-SC09. It is not the
// MC/TCP protocol used by Ethernet adapters, and it is not the FX Computer Link
// protocol used by every FX2N-232-BD/485-BD configuration.
package melsec_plc_fx2n

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/tarm/serial"
)

const (
	stx = byte(0x02)
	etx = byte(0x03)
	enq = byte(0x05)
	ack = byte(0x06)
	nak = byte(0x15)
)

const (
	ProtocolProgrammingPort = "programming_port"
	ProtocolComputerLink    = "computer_link"
)

// Config describes the PC-side serial port. The classic FX programming-port
// protocol commonly uses 9600 7E1, but the values must match the actual
// cable/MX Component setup.
type Config struct {
	Port            string
	Baud            int
	DataBits        int
	Parity          string
	StopBits        int
	TimeoutMs       int
	Protocol        string
	Station         byte
	MessageWait     byte
	DisableSumCheck bool
}

type serialPort interface {
	io.ReadWriteCloser
	Flush() error
}

type Client struct {
	mu       sync.Mutex
	cfg      Config
	port     serialPort
	openPort func(Config) (serialPort, error)
}

func New(cfg Config) *Client {
	return &Client{cfg: normalizeConfig(cfg), openPort: openSerialPort}
}

// SetConfig closes the current port and applies new serial settings. The next
// operation opens the port lazily.
func (c *Client) SetConfig(cfg Config) {
	c.mu.Lock()
	defer c.mu.Unlock()
	_ = c.closeLocked()
	c.cfg = normalizeConfig(cfg)
}

func (c *Client) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.closeLocked()
}

func (c *Client) TestConnection() error {
	_, err := c.ReadWord("D0")
	return err
}

// ReadWord reads one 16-bit value. D devices are read as data registers. X,
// Y, M and S devices are read as 16 consecutive bits and packed into a word.
func (c *Client) ReadWord(device string) (int16, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	dev, err := parseDevice(device)
	if err != nil {
		return 0, err
	}
	if c.cfg.Protocol == ProtocolComputerLink {
		return c.readComputerLinkWordLocked(dev)
	}
	address, byteCount, bitOffset, err := dev.readLocation()
	if err != nil {
		return 0, err
	}
	data, err := c.readBytesLocked(address, byteCount)
	if err != nil {
		return 0, fmt.Errorf("read %s: %w", dev.text, err)
	}
	if bitOffset == 0 && len(data) == 2 {
		return int16(binary.LittleEndian.Uint16(data)), nil
	}
	var packed uint32
	for i, value := range data {
		packed |= uint32(value) << (8 * i)
	}
	return int16((packed >> bitOffset) & 0xffff), nil
}

// WriteWord writes one 16-bit D register. The fill-oil application only writes
// D2 and D3; writing X/Y/M/S as words is intentionally rejected.
func (c *Client) WriteWord(device string, value int16) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	dev, err := parseDevice(device)
	if err != nil {
		return err
	}
	if c.cfg.Protocol == ProtocolComputerLink {
		return c.writeComputerLinkWordLocked(dev, uint16(value))
	}
	address, err := dev.wordAddress()
	if err != nil {
		return err
	}
	data := []byte{byte(value), byte(uint16(value) >> 8)}
	if err := c.writeBytesLocked(address, data); err != nil {
		return fmt.Errorf("write %s: %w", dev.text, err)
	}
	return nil
}

func (c *Client) readBytesLocked(address uint16, count byte) ([]byte, error) {
	request := buildReadCommand(address, count)
	var lastErr error
	for attempt := 0; attempt < 2; attempt++ {
		if err := c.ensureOpenLocked(); err != nil {
			lastErr = err
			continue
		}
		if err := c.port.Flush(); err != nil {
			lastErr = err
			_ = c.closeLocked()
			continue
		}
		if err := writeAll(c.port, request); err != nil {
			lastErr = err
			_ = c.closeLocked()
			continue
		}
		response, err := readDataResponse(c.port, int(count), c.timeout())
		if err == nil {
			return response, nil
		}
		lastErr = err
		_ = c.closeLocked()
	}
	return nil, fmt.Errorf("serial transaction failed after reopen: %w", lastErr)
}

func (c *Client) writeBytesLocked(address uint16, data []byte) error {
	request, err := buildWriteCommand(address, data)
	if err != nil {
		return err
	}
	var lastErr error
	for attempt := 0; attempt < 2; attempt++ {
		if err := c.ensureOpenLocked(); err != nil {
			lastErr = err
			continue
		}
		if err := c.port.Flush(); err != nil {
			lastErr = err
			_ = c.closeLocked()
			continue
		}
		if err := writeAll(c.port, request); err != nil {
			lastErr = err
			_ = c.closeLocked()
			continue
		}
		if err := readWriteResponse(c.port, c.timeout()); err == nil {
			return nil
		} else {
			lastErr = err
		}
		_ = c.closeLocked()
	}
	return fmt.Errorf("serial transaction failed after reopen: %w", lastErr)
}

func (c *Client) readComputerLinkWordLocked(dev device) (int16, error) {
	head, err := dev.computerLinkWordHead()
	if err != nil {
		return 0, err
	}
	request := buildComputerLinkRequest(c.cfg, "WR", head, 1, "")
	var lastErr error
	for attempt := 0; attempt < 2; attempt++ {
		if err := c.prepareTransactionLocked(); err != nil {
			lastErr = err
			continue
		}
		if err := writeAll(c.port, request); err != nil {
			lastErr = err
			_ = c.closeLocked()
			continue
		}
		data, err := readComputerLinkDataResponse(c.port, c.cfg, 4, c.timeout())
		if err == nil {
			if err = writeAll(c.port, buildComputerLinkAck(c.cfg.Station)); err == nil {
				value, parseErr := strconv.ParseUint(string(data), 16, 16)
				if parseErr != nil {
					return 0, fmt.Errorf("invalid Computer Link word %q: %w", data, parseErr)
				}
				return int16(uint16(value)), nil
			}
		}
		lastErr = err
		_ = c.closeLocked()
	}
	return 0, fmt.Errorf("Computer Link read %s failed after reopen: %w", dev.text, lastErr)
}

func (c *Client) writeComputerLinkWordLocked(dev device, value uint16) error {
	if dev.kind != 'D' {
		return fmt.Errorf("word write supports D registers only, got %s", dev.text)
	}
	head, err := dev.computerLinkWordHead()
	if err != nil {
		return err
	}
	request := buildComputerLinkRequest(c.cfg, "WW", head, 1, fmt.Sprintf("%04X", value))
	var lastErr error
	for attempt := 0; attempt < 2; attempt++ {
		if err := c.prepareTransactionLocked(); err != nil {
			lastErr = err
			continue
		}
		if err := writeAll(c.port, request); err != nil {
			lastErr = err
			_ = c.closeLocked()
			continue
		}
		if err := readComputerLinkWriteResponse(c.port, c.cfg, c.timeout()); err == nil {
			return nil
		} else {
			lastErr = err
		}
		_ = c.closeLocked()
	}
	return fmt.Errorf("Computer Link write %s failed after reopen: %w", dev.text, lastErr)
}

func (c *Client) prepareTransactionLocked() error {
	if err := validateConfig(c.cfg); err != nil {
		return err
	}
	if err := c.ensureOpenLocked(); err != nil {
		return err
	}
	if err := c.port.Flush(); err != nil {
		_ = c.closeLocked()
		return err
	}
	return nil
}

func (c *Client) ensureOpenLocked() error {
	if c.port != nil {
		return nil
	}
	if err := validateConfig(c.cfg); err != nil {
		return err
	}
	port, err := c.openPort(c.cfg)
	if err != nil {
		return fmt.Errorf("open PLC serial port %s: %w", c.cfg.Port, err)
	}
	c.port = port
	return nil
}

func validateConfig(cfg Config) error {
	switch cfg.Protocol {
	case ProtocolProgrammingPort, ProtocolComputerLink:
	default:
		return fmt.Errorf("unsupported FX2N protocol %q", cfg.Protocol)
	}
	if cfg.Protocol == ProtocolComputerLink {
		if cfg.Station > 15 {
			return fmt.Errorf("Computer Link station %d is outside 0..15", cfg.Station)
		}
		if cfg.MessageWait > 15 {
			return fmt.Errorf("Computer Link message wait %d is outside 0..15", cfg.MessageWait)
		}
	}
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

func (c *Client) timeout() time.Duration {
	return time.Duration(c.cfg.TimeoutMs) * time.Millisecond
}

func normalizeConfig(cfg Config) Config {
	cfg.Port = strings.TrimSpace(cfg.Port)
	if cfg.Baud <= 0 {
		cfg.Baud = 9600
	}
	if cfg.DataBits == 0 {
		cfg.DataBits = 7
	}
	if strings.TrimSpace(cfg.Parity) == "" {
		cfg.Parity = "E"
	}
	cfg.Parity = strings.ToUpper(strings.TrimSpace(cfg.Parity))
	if cfg.StopBits == 0 {
		cfg.StopBits = 1
	}
	if cfg.TimeoutMs <= 0 {
		cfg.TimeoutMs = 1000
	}
	cfg.Protocol = strings.ToLower(strings.TrimSpace(cfg.Protocol))
	if cfg.Protocol == "" {
		cfg.Protocol = ProtocolProgrammingPort
	}
	return cfg
}

func openSerialPort(cfg Config) (serialPort, error) {
	if cfg.Port == "" {
		return nil, errors.New("PLC serial port is empty")
	}
	parity, err := serialParity(cfg.Parity)
	if err != nil {
		return nil, err
	}
	stopBits, err := serialStopBits(cfg.StopBits)
	if err != nil {
		return nil, err
	}
	if cfg.DataBits < 5 || cfg.DataBits > 8 {
		return nil, fmt.Errorf("unsupported data bits %d", cfg.DataBits)
	}
	return serial.OpenPort(&serial.Config{
		Name:        cfg.Port,
		Baud:        cfg.Baud,
		ReadTimeout: time.Duration(cfg.TimeoutMs) * time.Millisecond,
		Size:        byte(cfg.DataBits),
		Parity:      parity,
		StopBits:    stopBits,
	})
}

func serialParity(value string) (serial.Parity, error) {
	switch strings.ToUpper(strings.TrimSpace(value)) {
	case "N", "NONE":
		return serial.ParityNone, nil
	case "E", "EVEN":
		return serial.ParityEven, nil
	case "O", "ODD":
		return serial.ParityOdd, nil
	default:
		return 0, fmt.Errorf("unsupported parity %q", value)
	}
}

func serialStopBits(value int) (serial.StopBits, error) {
	switch value {
	case 1:
		return serial.Stop1, nil
	case 2:
		return serial.Stop2, nil
	default:
		return 0, fmt.Errorf("unsupported stop bits %d", value)
	}
}

type device struct {
	kind    byte
	address uint16
	text    string
}

func parseDevice(value string) (device, error) {
	value = strings.ToUpper(strings.TrimSpace(value))
	if len(value) < 2 {
		return device{}, fmt.Errorf("invalid FX2N device %q", value)
	}
	kind := value[0]
	base := 10
	if kind == 'X' || kind == 'Y' {
		base = 8
	}
	if kind != 'D' && kind != 'X' && kind != 'Y' && kind != 'M' && kind != 'S' {
		return device{}, fmt.Errorf("unsupported FX2N device %q", value)
	}
	address, err := strconv.ParseUint(value[1:], base, 16)
	if err != nil {
		return device{}, fmt.Errorf("invalid FX2N device %q: %w", value, err)
	}
	return device{kind: kind, address: uint16(address), text: value}, nil
}

func (d device) wordAddress() (uint16, error) {
	if d.kind != 'D' {
		return 0, fmt.Errorf("word write supports D registers only, got %s", d.text)
	}
	switch {
	case d.address <= 511:
		return 0x1000 + d.address*2, nil
	case d.address >= 8000 && d.address <= 8255:
		return 0x0e00 + (d.address-8000)*2, nil
	default:
		return 0, fmt.Errorf("D register out of FX programming-port range: %s", d.text)
	}
}

func (d device) readLocation() (address uint16, byteCount byte, bitOffset uint, err error) {
	if d.kind == 'D' {
		address, err = d.wordAddress()
		return address, 2, 0, err
	}
	var base uint16
	switch d.kind {
	case 'X':
		if d.address > 0x7f {
			return 0, 0, 0, fmt.Errorf("X device out of range: %s", d.text)
		}
		base = 0x0080
	case 'Y':
		if d.address > 0x7f {
			return 0, 0, 0, fmt.Errorf("Y device out of range: %s", d.text)
		}
		base = 0x00a0
	case 'M':
		if d.address < 8000 {
			if d.address > 1023 {
				return 0, 0, 0, fmt.Errorf("M device out of range: %s", d.text)
			}
			base = 0x0100
		} else {
			if d.address > 8255 {
				return 0, 0, 0, fmt.Errorf("M device out of range: %s", d.text)
			}
			base = 0x01e0
			d.address -= 8000
		}
	case 'S':
		if d.address > 999 {
			return 0, 0, 0, fmt.Errorf("S device out of range: %s", d.text)
		}
		base = 0
	default:
		return 0, 0, 0, fmt.Errorf("unsupported bit device %s", d.text)
	}
	bitOffset = uint(d.address % 8)
	address = base + d.address/8
	byteCount = byte((bitOffset + 16 + 7) / 8)
	return address, byteCount, bitOffset, nil
}

func (d device) computerLinkWordHead() (string, error) {
	switch d.kind {
	case 'D':
		if d.address > 9999 {
			return "", fmt.Errorf("D register out of Computer Link range: %s", d.text)
		}
		return fmt.Sprintf("D%04d", d.address), nil
	case 'X', 'Y':
		if d.address%8 != 0 {
			return "", fmt.Errorf("Computer Link word read requires %c address ending in octal 0: %s", d.kind, d.text)
		}
		if d.address > 0o7777 {
			return "", fmt.Errorf("%c device out of Computer Link range: %s", d.kind, d.text)
		}
		return fmt.Sprintf("%c%04o", d.kind, d.address), nil
	case 'M', 'S':
		if d.address%8 != 0 {
			return "", fmt.Errorf("Computer Link word read requires %c address divisible by 8: %s", d.kind, d.text)
		}
		if d.address > 9999 {
			return "", fmt.Errorf("%c device out of Computer Link range: %s", d.kind, d.text)
		}
		return fmt.Sprintf("%c%04d", d.kind, d.address), nil
	default:
		return "", fmt.Errorf("unsupported Computer Link device %s", d.text)
	}
}

func buildComputerLinkRequest(cfg Config, command, head string, count byte, data string) []byte {
	payload := fmt.Sprintf("%02XFF%s%X%s%02X%s", cfg.Station, command, cfg.MessageWait, head, count, data)
	frame := make([]byte, 1, 1+len(payload)+2)
	frame[0] = enq
	frame = append(frame, payload...)
	if !cfg.DisableSumCheck {
		frame = append(frame, asciiSum(frame[1:])...)
	}
	return frame
}

func buildComputerLinkAck(station byte) []byte {
	return []byte{ack, hexDigit(station >> 4), hexDigit(station), 'F', 'F'}
}

func readComputerLinkDataResponse(r io.Reader, cfg Config, dataChars int, timeout time.Duration) ([]byte, error) {
	marker, err := readMarker(r, timeout, stx, nak)
	if err != nil {
		return nil, err
	}
	if marker == nak {
		return nil, readComputerLinkNAK(r, cfg)
	}
	sumChars := 0
	if !cfg.DisableSumCheck {
		sumChars = 2
	}
	rest := make([]byte, 2+2+dataChars+1+sumChars)
	if _, err := io.ReadFull(r, rest); err != nil {
		return nil, fmt.Errorf("read Computer Link data response: %w", err)
	}
	frame := append([]byte{stx}, rest...)
	if err := validateComputerLinkAddress(frame[1:5], cfg.Station); err != nil {
		return nil, err
	}
	etxIndex := 1 + 2 + 2 + dataChars
	if frame[etxIndex] != etx {
		return nil, fmt.Errorf("Computer Link response framing is invalid: % X", frame)
	}
	if !cfg.DisableSumCheck {
		want := asciiSum(frame[1 : etxIndex+1])
		if !bytesEqualFold(frame[etxIndex+1:], want) {
			return nil, fmt.Errorf("Computer Link response checksum %q, want %q", frame[etxIndex+1:], want)
		}
	}
	data := append([]byte(nil), frame[5:5+dataChars]...)
	return data, nil
}

func readComputerLinkWriteResponse(r io.Reader, cfg Config, timeout time.Duration) error {
	marker, err := readMarker(r, timeout, ack, nak)
	if err != nil {
		return err
	}
	if marker == nak {
		return readComputerLinkNAK(r, cfg)
	}
	address := make([]byte, 4)
	if _, err := io.ReadFull(r, address); err != nil {
		return fmt.Errorf("read Computer Link ACK: %w", err)
	}
	return validateComputerLinkAddress(address, cfg.Station)
}

func readComputerLinkNAK(r io.Reader, cfg Config) error {
	rest := make([]byte, 6)
	if _, err := io.ReadFull(r, rest); err != nil {
		return fmt.Errorf("read Computer Link NAK: %w", err)
	}
	if err := validateComputerLinkAddress(rest[:4], cfg.Station); err != nil {
		return err
	}
	return fmt.Errorf("PLC returned Computer Link error %sH", rest[4:])
}

func validateComputerLinkAddress(value []byte, station byte) error {
	want := []byte{hexDigit(station >> 4), hexDigit(station), 'F', 'F'}
	if !bytesEqualFold(value, want) {
		return fmt.Errorf("Computer Link response address %q, want %q", value, want)
	}
	return nil
}

func asciiSum(data []byte) []byte {
	var sum byte
	for _, value := range data {
		sum += value
	}
	return []byte{hexDigit(sum >> 4), hexDigit(sum)}
}

func hexDigit(value byte) byte {
	value &= 0x0f
	if value < 10 {
		return '0' + value
	}
	return 'A' + value - 10
}

func bytesEqualFold(left, right []byte) bool {
	return strings.EqualFold(string(left), string(right))
}

func buildReadCommand(address uint16, count byte) []byte {
	body := fmt.Sprintf("0%04X%02X%c", address, count, etx)
	return withFrame(body)
}

func buildWriteCommand(address uint16, data []byte) ([]byte, error) {
	if len(data) == 0 || len(data) > 255 {
		return nil, fmt.Errorf("invalid write byte count %d", len(data))
	}
	var payload strings.Builder
	for _, value := range data {
		fmt.Fprintf(&payload, "%02X", value)
	}
	body := fmt.Sprintf("1%04X%02X%s%c", address, len(data), payload.String(), etx)
	return withFrame(body), nil
}

func withFrame(body string) []byte {
	frame := make([]byte, 1, 1+len(body)+2)
	frame[0] = stx
	frame = append(frame, body...)
	var sum byte
	for _, value := range frame[1:] {
		sum += value
	}
	frame = append(frame, fmt.Sprintf("%02X", sum)...)
	return frame
}

func readDataResponse(r io.Reader, byteCount int, timeout time.Duration) ([]byte, error) {
	marker, err := readMarker(r, timeout, stx, nak)
	if err != nil {
		return nil, err
	}
	if marker == nak {
		return nil, errors.New("PLC returned NAK")
	}
	frame := make([]byte, byteCount*2+4)
	frame[0] = stx
	if _, err := io.ReadFull(r, frame[1:]); err != nil {
		return nil, fmt.Errorf("read PLC data response: %w", err)
	}
	if err := validateDataFrame(frame, byteCount); err != nil {
		return nil, err
	}
	data := make([]byte, byteCount)
	for i := range data {
		value, err := strconv.ParseUint(string(frame[1+i*2:3+i*2]), 16, 8)
		if err != nil {
			return nil, fmt.Errorf("invalid PLC hex data: %w", err)
		}
		data[i] = byte(value)
	}
	return data, nil
}

func readWriteResponse(r io.Reader, timeout time.Duration) error {
	marker, err := readMarker(r, timeout, ack, nak)
	if err != nil {
		return err
	}
	if marker == nak {
		return errors.New("PLC returned NAK")
	}
	return nil
}

func readMarker(r io.Reader, timeout time.Duration, accepted ...byte) (byte, error) {
	deadline := time.Now().Add(timeout)
	var one [1]byte
	for time.Now().Before(deadline) {
		n, err := r.Read(one[:])
		if n == 1 {
			for _, marker := range accepted {
				if one[0] == marker {
					return one[0], nil
				}
			}
		}
		if err != nil {
			return 0, err
		}
	}
	return 0, errors.New("PLC serial response timeout")
}

func validateDataFrame(frame []byte, byteCount int) error {
	wantLength := byteCount*2 + 4
	if len(frame) != wantLength {
		return fmt.Errorf("PLC response length %d, want %d", len(frame), wantLength)
	}
	if frame[0] != stx || frame[len(frame)-3] != etx {
		return fmt.Errorf("PLC response framing is invalid: % X", frame)
	}
	var sum byte
	for _, value := range frame[1 : len(frame)-2] {
		sum += value
	}
	want := fmt.Sprintf("%02X", sum)
	if !strings.EqualFold(string(frame[len(frame)-2:]), want) {
		return fmt.Errorf("PLC response checksum %q, want %q", frame[len(frame)-2:], want)
	}
	return nil
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
