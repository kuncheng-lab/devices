package siemens_s7

import (
	"encoding/binary"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/robinson/gos7"
)

type Config struct {
	Address     string
	Rack        int
	Slot        int
	Timeout     time.Duration
	IdleTimeout time.Duration
}

type Client struct {
	mu      sync.Mutex
	cfg     Config
	handler *gos7.TCPClientHandler
	client  gos7.Client
}

func New(cfg Config) *Client {
	if cfg.Address == "" {
		cfg.Address = "192.168.0.10"
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 800 * time.Millisecond
	}
	if cfg.IdleTimeout <= 0 {
		cfg.IdleTimeout = 3 * time.Second
	}
	return &Client{cfg: cfg}
}

func (c *Client) Close() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.closeLocked()
}

func (c *Client) ReadDB(db, start, size int) ([]byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.connectLocked(); err != nil {
		return nil, err
	}
	buf := make([]byte, size)
	if err := c.client.AGReadDB(db, start, size, buf); err != nil {
		c.closeLocked()
		return nil, fmt.Errorf("read DB%d.DBB%d len %d: %w", db, start, size, explainS7ReadError(db, start, size, err))
	}
	return buf, nil
}

// ReadEB reads bytes from the PLC input area. Siemens documentation calls
// this area I (input); gos7 uses the German abbreviation EB (Eingangsbyte).
func (c *Client) ReadEB(start, size int) ([]byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.connectLocked(); err != nil {
		return nil, err
	}
	buf := make([]byte, size)
	if err := c.client.AGReadEB(start, size, buf); err != nil {
		c.closeLocked()
		return nil, fmt.Errorf("read EB%d len %d: %w", start, size, err)
	}
	return buf, nil
}

func (c *Client) WriteDB(db, start int, data []byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.connectLocked(); err != nil {
		return err
	}
	if err := c.client.AGWriteDB(db, start, len(data), data); err != nil {
		c.closeLocked()
		return fmt.Errorf("write DB%d.DBB%d len %d: %w", db, start, len(data), err)
	}
	return nil
}

// SetDBBit writes one DB bit with an S7 Write Var bit request. This matches
// HslCommunication's SiemensS7Net.Write("Vx.y", bool) behavior used by the
// original application and avoids a read-modify-write race on adjacent bits.
// S7-200 SMART exposes V memory through DB1 when using S7 communication.
func (c *Client) SetDBBit(db, byteOffset, bit int, value bool) error {
	request, err := buildS7DBBitWriteRequest(db, byteOffset, bit, value)
	if err != nil {
		return err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.connectLocked(); err != nil {
		return err
	}
	response, err := c.handler.Send(request)
	if err != nil {
		c.closeLocked()
		return fmt.Errorf("write DB%d.DBX%d.%d: %w", db, byteOffset, bit, err)
	}
	if err := parseS7WriteResponse(response); err != nil {
		c.closeLocked()
		return fmt.Errorf("write DB%d.DBX%d.%d: %w", db, byteOffset, bit, err)
	}
	return nil
}

func buildS7DBBitWriteRequest(db, byteOffset, bit int, value bool) ([]byte, error) {
	if db < 0 || db > 0xffff {
		return nil, fmt.Errorf("invalid DB number %d", db)
	}
	if byteOffset < 0 {
		return nil, fmt.Errorf("invalid byte offset %d", byteOffset)
	}
	if bit < 0 || bit > 7 {
		return nil, fmt.Errorf("invalid bit offset %d", bit)
	}
	bitAddress := uint64(byteOffset)*8 + uint64(bit)
	if bitAddress > 0xffffff {
		return nil, fmt.Errorf("DB bit address DB%d.DBX%d.%d exceeds S7 address range", db, byteOffset, bit)
	}

	// TPKT + COTP + S7 Write Var, one item, one bit. The layout is the same
	// as HslCommunication SiemensS7Net.BuildWriteBitCommand.
	request := []byte{
		0x03, 0x00, 0x00, 0x24, 0x02, 0xf0, 0x80,
		0x32, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x0e, 0x00, 0x05,
		0x05, 0x01, 0x12, 0x0a, 0x10, 0x01, 0x00, 0x01,
		byte(db >> 8), byte(db), 0x84,
		byte(bitAddress >> 16), byte(bitAddress >> 8), byte(bitAddress),
		0x00, 0x03, 0x00, 0x01, 0x00,
	}
	if value {
		request[35] = 1
	}
	return request, nil
}

func parseS7WriteResponse(response []byte) error {
	if len(response) != 22 {
		return fmt.Errorf("invalid S7 write response length %d, want 22", len(response))
	}
	if response[0] != 0x03 || response[7] != 0x32 || response[8] != 0x03 {
		return fmt.Errorf("invalid S7 write response header")
	}
	if int(binary.BigEndian.Uint16(response[2:4])) != len(response) {
		return fmt.Errorf("invalid S7 write response TPKT length %d", binary.BigEndian.Uint16(response[2:4]))
	}
	if response[17] != 0 || response[18] != 0 {
		return fmt.Errorf("S7 write response error class=0x%02X code=0x%02X", response[17], response[18])
	}
	if response[19] != 0x05 || response[20] != 0x01 {
		return fmt.Errorf("invalid S7 Write Var acknowledgement")
	}
	if response[21] != 0xff {
		return fmt.Errorf("S7 bit write rejected with item code 0x%02X", response[21])
	}
	return nil
}

func (c *Client) PulseDBBit(db, byteOffset, bit int, duration time.Duration) error {
	if bit < 0 || bit > 7 {
		return fmt.Errorf("invalid bit offset %d", bit)
	}
	if duration <= 0 {
		duration = 120 * time.Millisecond
	}
	if err := c.SetDBBit(db, byteOffset, bit, true); err != nil {
		return err
	}
	time.Sleep(duration)
	return c.SetDBBit(db, byteOffset, bit, false)
}

func (c *Client) connectLocked() error {
	if c.client != nil {
		return nil
	}
		handler := gos7.NewTCPClientHandlerWithConnectType(c.cfg.Address, c.cfg.Rack, c.cfg.Slot, 2)
	handler.Timeout = c.cfg.Timeout
	handler.IdleTimeout = c.cfg.IdleTimeout
	if err := handler.Connect(); err != nil {
		_ = handler.Close()
		return fmt.Errorf("connect Siemens S7 %s rack %d slot %d: %w", c.cfg.Address, c.cfg.Rack, c.cfg.Slot, err)
	}
	c.handler = handler
	c.client = gos7.NewClient(handler)
	return nil
}

func (c *Client) closeLocked() {
	if c.handler != nil {
		_ = c.handler.Close()
	}
	c.handler = nil
	c.client = nil
}

func explainS7ReadError(db, start, size int, err error) error {
	if err == nil {
		return nil
	}
	if strings.Contains(err.Error(), "Invalid Buffer passed to Send/Receive") {
		return fmt.Errorf("%w；PLC返回了短响应，通常表示DB访问被拒绝或地址无效。请检查PLC已启用PUT/GET访问、DB%d存在且长度至少到DBB%d、该DB关闭优化块访问，并确认机架/槽号正确", err, db, start+size-1)
	}
	return err
}

func BoolAt(buf []byte, byteOffset, bit int) bool {
	if byteOffset < 0 || byteOffset >= len(buf) || bit < 0 || bit > 7 {
		return false
	}
	return buf[byteOffset]&(1<<bit) != 0
}

func Int16At(buf []byte, byteOffset int) int16 {
	if byteOffset < 0 || byteOffset+2 > len(buf) {
		return 0
	}
	return int16(binary.BigEndian.Uint16(buf[byteOffset:]))
}

func Uint16At(buf []byte, byteOffset int) uint16 {
	if byteOffset < 0 || byteOffset+2 > len(buf) {
		return 0
	}
	return binary.BigEndian.Uint16(buf[byteOffset:])
}

func Int32At(buf []byte, byteOffset int) int32 {
	if byteOffset < 0 || byteOffset+4 > len(buf) {
		return 0
	}
	return int32(binary.BigEndian.Uint32(buf[byteOffset:]))
}

func PutInt16(buf []byte, byteOffset int, v int16) {
	if byteOffset < 0 || byteOffset+2 > len(buf) {
		return
	}
	binary.BigEndian.PutUint16(buf[byteOffset:], uint16(v))
}

func PutUint16(buf []byte, byteOffset int, v uint16) {
	if byteOffset < 0 || byteOffset+2 > len(buf) {
		return
	}
	binary.BigEndian.PutUint16(buf[byteOffset:], v)
}

func PutInt32(buf []byte, byteOffset int, v int32) {
	if byteOffset < 0 || byteOffset+4 > len(buf) {
		return
	}
	binary.BigEndian.PutUint32(buf[byteOffset:], uint32(v))
}
