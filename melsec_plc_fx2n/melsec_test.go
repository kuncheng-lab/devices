package melsec_plc_fx2n

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"testing"
	"time"
)

func TestBuildReadD2(t *testing.T) {
	dev, err := parseDevice("D2")
	if err != nil {
		t.Fatal(err)
	}
	address, err := dev.wordAddress()
	if err != nil {
		t.Fatal(err)
	}
	got := buildReadCommand(address, 2)
	want := []byte{stx, '0', '1', '0', '0', '4', '0', '2', etx, '5', 'A'}
	if !bytes.Equal(got, want) {
		t.Fatalf("got % X, want % X", got, want)
	}
}

func TestClassicProgrammingPortDefaults(t *testing.T) {
	cfg := normalizeConfig(Config{Port: "COM6"})
	if cfg.Baud != 9600 || cfg.DataBits != 7 || cfg.Parity != "E" || cfg.StopBits != 1 || cfg.Protocol != ProtocolProgrammingPort {
		t.Fatalf("defaults=%d %d%s%d, want 9600 7E1", cfg.Baud, cfg.DataBits, cfg.Parity, cfg.StopBits)
	}
}

func TestComputerLinkOfficialManualFrames(t *testing.T) {
	cfg := Config{Protocol: ProtocolComputerLink, Station: 5}
	read := buildComputerLinkRequest(cfg, "WR", "TN123", 2, "")
	wantRead := append([]byte{enq}, []byte("05FFWR0TN1230264")...)
	if !bytes.Equal(read, wantRead) {
		t.Fatalf("read frame=%q, want %q", read, wantRead)
	}

	cfg.Station = 0
	write := buildComputerLinkRequest(cfg, "WW", "D0000", 2, "1234ACD7")
	wantWrite := append([]byte{enq}, []byte("00FFWW0D0000021234ACD7F9")...)
	if !bytes.Equal(write, wantWrite) {
		t.Fatalf("write frame=%q, want %q", write, wantWrite)
	}
}

func TestComputerLinkReadX0AndAcknowledge(t *testing.T) {
	cfg := Config{Port: "COM6", Protocol: ProtocolComputerLink, Station: 0}
	port := &scriptedPort{responses: [][]byte{computerLinkDataFrame(0, "C000", true)}}
	client := New(cfg)
	client.openPort = func(Config) (serialPort, error) { return port, nil }

	got, err := client.ReadWord("X0")
	if err != nil {
		t.Fatal(err)
	}
	if uint16(got) != 0xc000 {
		t.Fatalf("X0=%#04x, want 0xc000", uint16(got))
	}
	if len(port.writes) != 2 {
		t.Fatalf("writes=%d, want request plus ACK", len(port.writes))
	}
	wantRequest := buildComputerLinkRequest(normalizeConfig(cfg), "WR", "X0000", 1, "")
	if !bytes.Equal(port.writes[0], wantRequest) {
		t.Fatalf("request=%q, want %q", port.writes[0], wantRequest)
	}
	if wantAck := buildComputerLinkAck(0); !bytes.Equal(port.writes[1], wantAck) {
		t.Fatalf("ACK=% X, want % X", port.writes[1], wantAck)
	}
}

func TestComputerLinkWriteD2(t *testing.T) {
	cfg := Config{Port: "COM6", Protocol: ProtocolComputerLink, Station: 0}
	port := &scriptedPort{responses: [][]byte{{ack, '0', '0', 'F', 'F'}}}
	client := New(cfg)
	client.openPort = func(Config) (serialPort, error) { return port, nil }

	if err := client.WriteWord("D2", 10); err != nil {
		t.Fatal(err)
	}
	want := buildComputerLinkRequest(normalizeConfig(cfg), "WW", "D0002", 1, "000A")
	if len(port.writes) != 1 || !bytes.Equal(port.writes[0], want) {
		t.Fatalf("write=%q, want %q", port.writes[0], want)
	}
}

func TestComputerLinkRejectsBadChecksum(t *testing.T) {
	frame := computerLinkDataFrame(0, "1234", true)
	frame[len(frame)-1] = '0'
	if _, err := readComputerLinkDataResponse(bytes.NewReader(frame), Config{}, 4, time.Second); err == nil {
		t.Fatal("bad Computer Link checksum was accepted")
	}
}

func TestBuildWriteD2Value10(t *testing.T) {
	dev, err := parseDevice("D2")
	if err != nil {
		t.Fatal(err)
	}
	address, err := dev.wordAddress()
	if err != nil {
		t.Fatal(err)
	}
	got, err := buildWriteCommand(address, []byte{10, 0})
	if err != nil {
		t.Fatal(err)
	}
	want := withFrame("11004020A00" + string(etx))
	if !bytes.Equal(got, want) {
		t.Fatalf("got % X, want % X", got, want)
	}
}

func TestXAndYUseOctalAddresses(t *testing.T) {
	tests := []struct {
		device  string
		address uint16
		offset  uint
	}{
		{"X0", 0x0080, 0},
		{"X16", 0x0081, 6},
		{"X17", 0x0081, 7},
		{"Y0", 0x00a0, 0},
		{"Y14", 0x00a1, 4},
	}
	for _, test := range tests {
		dev, err := parseDevice(test.device)
		if err != nil {
			t.Fatalf("parse %s: %v", test.device, err)
		}
		address, _, offset, err := dev.readLocation()
		if err != nil {
			t.Fatalf("location %s: %v", test.device, err)
		}
		if address != test.address || offset != test.offset {
			t.Fatalf("%s address=%#04x offset=%d, want %#04x/%d", test.device, address, offset, test.address, test.offset)
		}
	}
}

func TestReadWordX0AndWriteD3OverPersistentPort(t *testing.T) {
	readResponse := dataFrame([]byte{0x00, 0xc0})
	port := &scriptedPort{responses: [][]byte{readResponse, {ack}}}
	client := New(Config{Port: "COM6"})
	client.openPort = func(Config) (serialPort, error) { return port, nil }

	got, err := client.ReadWord("X0")
	if err != nil {
		t.Fatal(err)
	}
	if uint16(got) != 0xc000 {
		t.Fatalf("X0=%#04x, want 0xc000", uint16(got))
	}
	if err := client.WriteWord("D3", 0x0080); err != nil {
		t.Fatal(err)
	}
	if port.closeCount != 0 {
		t.Fatalf("persistent port closed %d times", port.closeCount)
	}
	if len(port.writes) != 2 {
		t.Fatalf("writes=%d, want 2", len(port.writes))
	}
	if !bytes.Equal(port.writes[0], buildReadCommand(0x0080, 2)) {
		t.Fatalf("X0 request=% X", port.writes[0])
	}
	wantWrite, _ := buildWriteCommand(0x1006, []byte{0x80, 0x00})
	if !bytes.Equal(port.writes[1], wantWrite) {
		t.Fatalf("D3 request=% X, want % X", port.writes[1], wantWrite)
	}
}

func TestReadResponseRejectsBadChecksum(t *testing.T) {
	frame := dataFrame([]byte{0x34, 0x12})
	frame[len(frame)-1] = '0'
	if _, err := readDataResponse(bytes.NewReader(frame), 2, time.Second); err == nil {
		t.Fatal("bad checksum was accepted")
	}
}

func dataFrame(data []byte) []byte {
	var body bytes.Buffer
	for _, value := range data {
		fmt.Fprintf(&body, "%02X", value)
	}
	body.WriteByte(etx)
	return withFrame(body.String())
}

func computerLinkDataFrame(station byte, data string, sumCheck bool) []byte {
	body := fmt.Sprintf("%02XFF%s", station, data)
	frame := append([]byte{stx}, body...)
	frame = append(frame, etx)
	if sumCheck {
		frame = append(frame, asciiSum(frame[1:])...)
	}
	return frame
}

type scriptedPort struct {
	responses  [][]byte
	current    *bytes.Reader
	writes     [][]byte
	closeCount int
}

func (p *scriptedPort) Read(dst []byte) (int, error) {
	for p.current == nil || p.current.Len() == 0 {
		if len(p.responses) == 0 {
			return 0, io.EOF
		}
		p.current = bytes.NewReader(p.responses[0])
		p.responses = p.responses[1:]
	}
	return p.current.Read(dst)
}

func (p *scriptedPort) Write(src []byte) (int, error) {
	p.writes = append(p.writes, append([]byte(nil), src...))
	return len(src), nil
}

func (p *scriptedPort) Flush() error { return nil }

func (p *scriptedPort) Close() error {
	p.closeCount++
	return nil
}

func TestDWordIsLittleEndian(t *testing.T) {
	frame := dataFrame([]byte{0x34, 0x12})
	data, err := readDataResponse(bytes.NewReader(frame), 2, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if got := binary.LittleEndian.Uint16(data); got != 0x1234 {
		t.Fatalf("got %#04x, want 0x1234", got)
	}
}
