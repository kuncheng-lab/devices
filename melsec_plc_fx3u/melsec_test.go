package melsec_plc_fx3u

import (
	"encoding/binary"
	"encoding/hex"
	"io"
	"net"
	"strconv"
	"sync/atomic"
	"testing"
	"time"
)

func TestBuildBinaryWriteD0(t *testing.T) {
	dev, err := parseDevice("D0")
	if err != nil {
		t.Fatal(err)
	}
	got := buildBinaryWrite(dev, 16, []int16{1})
	want := []byte{0x03, 0xFF, 0x10, 0x00, 0, 0, 0, 0, 0x20, 0x44, 1, 0, 1, 0}
	if hex.EncodeToString(got) != hex.EncodeToString(want) {
		t.Fatalf("got % X, want % X", got, want)
	}
}

func TestPersistentConnectionHandlesMultipleTransactions(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	var accepts int32
	done := make(chan error, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			done <- err
			return
		}
		atomic.AddInt32(&accepts, 1)
		defer conn.Close()
		for i := 1; i <= 2; i++ {
			req := make([]byte, 12)
			if _, err := io.ReadFull(conn, req); err != nil {
				done <- err
				return
			}
			resp := []byte{0x81, 0, 0, 0}
			binary.LittleEndian.PutUint16(resp[2:], uint16(i))
			if _, err := conn.Write(resp); err != nil {
				done <- err
				return
			}
		}
		done <- nil
	}()

	host, portText, err := net.SplitHostPort(ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		t.Fatal(err)
	}
	client := New(Config{Host: host, Port: port, TimeoutMs: 500, MonitoringTimer: 16})
	defer client.Close()
	for want := int16(1); want <= 2; want++ {
		got, err := client.ReadWord("D0")
		if err != nil {
			t.Fatal(err)
		}
		if got != want {
			t.Fatalf("got %d, want %d", got, want)
		}
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if got := atomic.LoadInt32(&accepts); got != 1 {
		t.Fatalf("accepted %d connections, want one persistent connection", got)
	}
}

func TestOctalBitDeviceAddresses(t *testing.T) {
	for _, tc := range []struct {
		name string
		want uint32
	}{
		{"X16", 14},
		{"X17", 15},
		{"Y14", 12},
		{"Y17", 15},
	} {
		dev, err := parseDevice(tc.name)
		if err != nil {
			t.Fatalf("parse %s: %v", tc.name, err)
		}
		if dev.address != tc.want {
			t.Fatalf("%s address=%d, want %d", tc.name, dev.address, tc.want)
		}
	}
}

func TestConnectionRequiresProtocolResponse(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		time.Sleep(100 * time.Millisecond)
	}()

	host, portText, err := net.SplitHostPort(ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	port, err := net.LookupPort("tcp", portText)
	if err != nil {
		t.Fatal(err)
	}
	client := &Client{
		host:    host,
		port:    port,
		timeout: 50 * time.Millisecond,
		timer:   16,
	}

	if err := client.TestConnection(); err == nil {
		t.Fatal("TestConnection succeeded without a PLC protocol response")
	}
	<-done
}
