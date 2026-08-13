package melsec_plc_fx5u

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"
	"testing"
	"time"
)

func TestBuildBinaryWordWriteD0(t *testing.T) {
	dev, err := parseDevice("D0")
	if err != nil {
		t.Fatal(err)
	}
	got := buildBinaryWordWrite(dev, 16, []int16{1})
	want := []byte{
		0x50, 0x00, 0x00, 0xFF, 0xFF, 0x03, 0x00, 0x0E, 0x00,
		0x10, 0x00, 0x01, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00,
		0xA8, 0x01, 0x00, 0x01, 0x00,
	}
	if hex.EncodeToString(got) != hex.EncodeToString(want) {
		t.Fatalf("got % X, want % X", got, want)
	}
}

func TestBuildBinaryBitWriteM101(t *testing.T) {
	dev, err := parseDevice("M101")
	if err != nil {
		t.Fatal(err)
	}
	got := buildBinaryBitWrite(dev, 16, []bool{true})
	want := []byte{
		0x50, 0x00, 0x00, 0xFF, 0xFF, 0x03, 0x00, 0x0D, 0x00,
		0x10, 0x00, 0x01, 0x14, 0x01, 0x00, 0x65, 0x00, 0x00,
		0x90, 0x01, 0x00, 0x10,
	}
	if hex.EncodeToString(got) != hex.EncodeToString(want) {
		t.Fatalf("got % X, want % X", got, want)
	}
}

func TestBinaryRequestLengthMatchesBody(t *testing.T) {
	for name, req := range map[string][]byte{
		"read":     buildBinaryRead(mustDevice(t, "D0"), 16, 1),
		"word set": buildBinaryWordWrite(mustDevice(t, "D0"), 16, []int16{1}),
		"bit set":  buildBinaryBitWrite(mustDevice(t, "M101"), 16, []bool{true}),
	} {
		got := int(req[7]) | int(req[8])<<8
		want := len(req) - 9
		if got != want {
			t.Fatalf("%s length = %d, want %d", name, got, want)
		}
	}
}

func TestBuildASCIIReadD0(t *testing.T) {
	got := buildASCIIRead(mustDevice(t, "D0"), 16, 1)
	want := "500000FF03FF000018001004010000D*0000000001"
	if got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestBuildASCIIBitWriteM101(t *testing.T) {
	got := buildASCIIBitWrite(mustDevice(t, "M101"), 16, []bool{true})
	want := "500000FF03FF000019001014010001M*00010100011"
	if got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestBuildASCIIWordWriteD0(t *testing.T) {
	got := buildASCIIWordWrite(mustDevice(t, "D0"), 16, []int16{1})
	want := "500000FF03FF00001C001014010000D*00000000010001"
	if got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestValidateASCIIResponse(t *testing.T) {
	data, err := validateASCIIResponse([]byte("D00000FF03FF00000800001234"))
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "1234" {
		t.Fatalf("data = %q", string(data))
	}
}

func TestReadWordFallsBackToASCIIAfterBinaryNoResponse(t *testing.T) {
	wantASCII := buildASCIIRead(mustDevice(t, "D0"), 16, 1)
	client, done := startTwoAttemptPLC(t, func(binaryReq []byte) error {
		if len(binaryReq) == 0 || binaryReq[0] != 0x50 {
			return fmt.Errorf("binary request = % X", binaryReq)
		}
		return nil
	}, func(asciiReq string) ([]byte, error) {
		if asciiReq != wantASCII {
			return nil, fmt.Errorf("ASCII request = %q, want %q", asciiReq, wantASCII)
		}
		return []byte("D00000FF03FF00000800001234"), nil
	})

	value, err := client.ReadWord("D0")
	if err != nil {
		t.Fatal(err)
	}
	if value != 0x1234 {
		t.Fatalf("value = 0x%04X, want 0x1234", uint16(value))
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestWriteBitFallsBackToASCIIAfterBinaryNoResponse(t *testing.T) {
	wantASCII := buildASCIIBitWrite(mustDevice(t, "M101"), 16, []bool{true})
	client, done := startTwoAttemptPLC(t, func(binaryReq []byte) error {
		if len(binaryReq) == 0 || binaryReq[0] != 0x50 {
			return fmt.Errorf("binary request = % X", binaryReq)
		}
		return nil
	}, func(asciiReq string) ([]byte, error) {
		if asciiReq != wantASCII {
			return nil, fmt.Errorf("ASCII request = %q, want %q", asciiReq, wantASCII)
		}
		return []byte("D00000FF03FF0000040000"), nil
	})

	if err := client.WriteWord("M101", 1); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestPersistentBinaryConnectionIsReused(t *testing.T) {
	client, done := startPersistentBinaryPLC(t, 2)

	if err := client.WriteWord("M100", 1); err != nil {
		t.Fatal(err)
	}
	if err := client.WriteWord("M101", 1); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestPersistentBinaryConnectionReconnectsAfterServerClose(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		defer ln.Close()
		for i := 0; i < 2; i++ {
			conn, err := ln.Accept()
			if err != nil {
				done <- err
				return
			}
			if _, err := readBinaryTestRequest(conn); err != nil {
				_ = conn.Close()
				done <- err
				return
			}
			if _, err := conn.Write(binaryWriteSuccessResponse()); err != nil {
				_ = conn.Close()
				done <- err
				return
			}
			if err := conn.Close(); err != nil {
				done <- err
				return
			}
		}
		done <- nil
	}()

	client := testClientForListener(t, ln)
	if err := client.WriteWord("M100", 1); err != nil {
		t.Fatal(err)
	}
	if err := client.WriteWord("M101", 1); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestPersistentBinaryConnectionSerializesConcurrentRequests(t *testing.T) {
	const requestCount = 12
	client, done := startPersistentBinaryPLC(t, requestCount)

	var wg sync.WaitGroup
	errs := make(chan error, requestCount)
	for i := 0; i < requestCount; i++ {
		wg.Add(1)
		go func(address int) {
			defer wg.Done()
			errs <- client.WriteWord(fmt.Sprintf("M%d", address), 1)
		}(100 + i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func mustDevice(t *testing.T, text string) device {
	t.Helper()
	dev, err := parseDevice(text)
	if err != nil {
		t.Fatal(err)
	}
	return dev
}

func TestValidateBinaryResponse(t *testing.T) {
	resp := []byte{
		0xD0, 0x00, 0x00, 0xFF, 0xFF, 0x03, 0x00, 0x04, 0x00,
		0x00, 0x00, 0x34, 0x12,
	}
	data, err := validateBinaryResponse(resp)
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(data) != "3412" {
		t.Fatalf("data = % X", data)
	}
}

func startTwoAttemptPLC(t *testing.T, checkBinary func([]byte) error, handleASCII func(string) ([]byte, error)) (*Client, <-chan error) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		defer ln.Close()
		conn, err := ln.Accept()
		if err != nil {
			done <- err
			return
		}
		binaryReq, err := readTestRequest(conn)
		_ = conn.Close()
		if err != nil {
			done <- err
			return
		}
		if err := checkBinary(binaryReq); err != nil {
			done <- err
			return
		}

		conn, err = ln.Accept()
		if err != nil {
			done <- err
			return
		}
		defer conn.Close()
		asciiReq, err := readTestRequest(conn)
		if err != nil {
			done <- err
			return
		}
		resp, err := handleASCII(string(asciiReq))
		if err != nil {
			done <- err
			return
		}
		_, err = conn.Write(resp)
		done <- err
	}()

	return testClientForListener(t, ln), done
}

func startPersistentBinaryPLC(t *testing.T, requestCount int) (*Client, <-chan error) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			done <- err
			return
		}
		_ = ln.Close()
		defer conn.Close()
		for i := 0; i < requestCount; i++ {
			if _, err := readBinaryTestRequest(conn); err != nil {
				done <- err
				return
			}
			if _, err := conn.Write(binaryWriteSuccessResponse()); err != nil {
				done <- err
				return
			}
		}
		done <- nil
	}()
	return testClientForListener(t, ln), done
}

func testClientForListener(t *testing.T, ln net.Listener) *Client {
	t.Helper()
	_, portText, err := net.SplitHostPort(ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		t.Fatal(err)
	}
	client := New(Config{Host: "127.0.0.1", Port: port, TimeoutMs: 200, MonitoringTimer: 16})
	t.Cleanup(func() {
		_ = client.Close()
	})
	return client
}

func readBinaryTestRequest(conn net.Conn) ([]byte, error) {
	_ = conn.SetReadDeadline(time.Now().Add(time.Second))
	header := make([]byte, 9)
	if _, err := io.ReadFull(conn, header); err != nil {
		return nil, err
	}
	body := make([]byte, int(binary.LittleEndian.Uint16(header[7:9])))
	if _, err := io.ReadFull(conn, body); err != nil {
		return nil, err
	}
	return append(header, body...), nil
}

func binaryWriteSuccessResponse() []byte {
	return []byte{
		0xD0, 0x00, 0x00, 0xFF, 0xFF, 0x03, 0x00, 0x02, 0x00,
		0x00, 0x00,
	}
}

func readTestRequest(conn net.Conn) ([]byte, error) {
	_ = conn.SetReadDeadline(time.Now().Add(time.Second))
	buf := make([]byte, 256)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, err
	}
	return buf[:n], nil
}
