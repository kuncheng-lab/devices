package atlas_pf6000

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"
)

func TestConnectSessionRequiresHandshakeResponse(t *testing.T) {
	ln := listenLocal(t)
	defer ln.Close()

	done := make(chan struct{}, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			done <- struct{}{}
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(time.Second))
		_, _ = bufio.NewReader(conn).ReadString(0)
		done <- struct{}{}
	}()

	host, port := splitTCPAddr(t, ln.Addr().String())
	client := NewClient(nil)
	err := client.ConnectSession(host, port, 100)
	if err == nil {
		t.Fatal("ConnectSession succeeded without a PF6000 handshake response")
	}
	if client.Connected() {
		t.Fatal("client is connected after failed handshake")
	}
	<-done
}

func TestConnectSessionSucceedsAfterHandshake(t *testing.T) {
	ln := listenLocal(t)
	defer ln.Close()

	done := make(chan struct{}, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			done <- struct{}{}
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(time.Second))
		_, _ = bufio.NewReader(conn).ReadString(0)
		_, _ = conn.Write([]byte("002000020010    00  \x00"))
		<-done
	}()

	host, port := splitTCPAddr(t, ln.Addr().String())
	client := NewClient(nil)
	if err := client.ConnectSession(host, port, 500); err != nil {
		t.Fatalf("ConnectSession failed after handshake response: %v", err)
	}
	if !client.Connected() {
		t.Fatal("client is not connected after successful handshake")
	}
	client.Disconnect()
	done <- struct{}{}
}

func TestConnectSessionDoesNotAutoSubscribeResults(t *testing.T) {
	ln := listenLocal(t)
	defer ln.Close()

	nextFrame := make(chan string, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			nextFrame <- ""
			return
		}
		defer conn.Close()
		reader := bufio.NewReader(conn)
		_ = conn.SetDeadline(time.Now().Add(time.Second))
		_, _ = reader.ReadString(0)
		_, _ = conn.Write([]byte("002000020010    00  \x00"))
		_ = conn.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
		tx, err := reader.ReadString(0)
		if err != nil {
			nextFrame <- ""
			return
		}
		nextFrame <- tx
	}()

	host, port := splitTCPAddr(t, ln.Addr().String())
	client := NewClient(nil)
	if err := client.ConnectSession(host, port, 500); err != nil {
		t.Fatalf("ConnectSession failed after handshake response: %v", err)
	}
	defer client.Disconnect()

	if got := <-nextFrame; got != "" {
		t.Fatalf("ConnectSession sent unexpected frame after handshake: %q", got)
	}
}

func TestEnsureSubscriptionsUsesStationModeResultMID(t *testing.T) {
	cases := []struct {
		name         string
		multiSpindle bool
		resultMID    int
	}{
		{name: "single station", resultMID: 60},
		{name: "combo station", multiSpindle: true, resultMID: 100},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			ln := listenLocal(t)
			defer ln.Close()

			frames := make(chan []string, 1)
			go func() {
				conn, err := ln.Accept()
				if err != nil {
					frames <- nil
					return
				}
				defer conn.Close()
				reader := bufio.NewReader(conn)
				_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
				_, _ = reader.ReadString(0)
				_, _ = conn.Write(frameForTest(t, OpenProtocolProbeRequest{MID: 2, Revision: 1}))

				var got []string
				got = append(got, readFrameForTest(reader))
				_, _ = conn.Write(commandAcceptedFrameForTest(t, 14))
				_, _ = conn.Write(frameForTest(t, OpenProtocolProbeRequest{MID: 15, Revision: 1, Data: "001"}))
				got = append(got, readFrameForTest(reader))
				got = append(got, readFrameForTest(reader))
				_, _ = conn.Write(commandAcceptedFrameForTest(t, testCase.resultMID))
				frames <- got
			}()

			host, port := splitTCPAddr(t, ln.Addr().String())
			client := NewClient(nil)
			if err := client.ConnectSession(host, port, 500); err != nil {
				t.Fatalf("ConnectSession failed: %v", err)
			}
			defer client.Disconnect()

			if err := client.EnsureSubscriptions(testCase.multiSpindle, 500*time.Millisecond); err != nil {
				t.Fatalf("EnsureSubscriptions failed: %v", err)
			}
			got := <-frames
			want := []string{
				string(frameForTest(t, OpenProtocolProbeRequest{MID: 14, Revision: 1})),
				string(frameForTest(t, OpenProtocolProbeRequest{MID: 16, Revision: 1})),
				string(frameForTest(t, OpenProtocolProbeRequest{MID: testCase.resultMID, Revision: 1})),
			}
			if len(got) != len(want) {
				t.Fatalf("sent %d frames, want %d: %q", len(got), len(want), got)
			}
			for i := range want {
				if got[i] != want[i] {
					t.Fatalf("frame %d = %q, want %q", i, got[i], want[i])
				}
			}
		})
	}
}

func TestSubscriptionTimeoutRetriesThreeTimesAndDisconnects(t *testing.T) {
	ln := listenLocal(t)
	defer ln.Close()

	frames := make(chan []string, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			frames <- nil
			return
		}
		defer conn.Close()
		reader := bufio.NewReader(conn)
		_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
		_, _ = reader.ReadString(0)
		_, _ = conn.Write(frameForTest(t, OpenProtocolProbeRequest{MID: 2, Revision: 1}))
		var got []string
		for len(got) < commandMaxAttempts {
			got = append(got, readFrameForTest(reader))
		}
		_, _ = reader.ReadString(0)
		frames <- got
	}()

	host, port := splitTCPAddr(t, ln.Addr().String())
	client := NewClient(nil)
	if err := client.ConnectSession(host, port, 500); err != nil {
		t.Fatalf("ConnectSession failed: %v", err)
	}
	err := client.EnsureResultSubscription(false, 30*time.Millisecond)
	if err == nil || !strings.Contains(err.Error(), "连续 3 次") {
		t.Fatalf("EnsureResultSubscription error = %v", err)
	}
	if client.Connected() {
		t.Fatal("client remained connected after three missing command acknowledgements")
	}
	got := <-frames
	if len(got) != commandMaxAttempts {
		t.Fatalf("sent %d subscription attempts, want %d", len(got), commandMaxAttempts)
	}
	for i, frame := range got {
		want := string(frameForTest(t, OpenProtocolProbeRequest{MID: 60, Revision: 1}))
		if frame != want {
			t.Fatalf("attempt %d = %q, want %q", i+1, frame, want)
		}
	}
}

func TestSelectPsetForStationWaitsForConfirmation(t *testing.T) {
	ln := listenLocal(t)
	defer ln.Close()

	frames := make(chan []string, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			frames <- nil
			return
		}
		defer conn.Close()
		reader := bufio.NewReader(conn)
		_ = conn.SetDeadline(time.Now().Add(time.Second))
		_, _ = reader.ReadString(0)
		_, _ = conn.Write([]byte("002000020010    00  \x00"))

		var got []string
		got = append(got, readFrameForTest(reader))
		_, _ = conn.Write(commandAcceptedFrameForTest(t, 18))
		_, _ = conn.Write(frameForTest(t, OpenProtocolProbeRequest{MID: 15, Revision: 1, Station: 2, Data: "007"}))
		got = append(got, readFrameForTest(reader))
		time.Sleep(50 * time.Millisecond)
		frames <- got
	}()

	host, port := splitTCPAddr(t, ln.Addr().String())
	client := NewClient(nil)
	if err := client.ConnectSession(host, port, 500); err != nil {
		t.Fatalf("ConnectSession failed after handshake response: %v", err)
	}
	defer client.Disconnect()

	client.mu.Lock()
	client.psetSelectionSubscribed = true
	client.selectedPset = "001"
	client.resultSubscribed = true
	client.mu.Unlock()

	if err := client.SelectPsetForStationContext(context.Background(), "7", 2, 500*time.Millisecond); err != nil {
		t.Fatalf("SelectPsetForStationContext failed: %v", err)
	}

	got := <-frames
	want := []string{
		string(frameForTest(t, OpenProtocolProbeRequest{MID: 18, Revision: 1, Station: 2, Data: "007"})),
		string(frameForTest(t, OpenProtocolProbeRequest{MID: 16, Revision: 1, Station: 2})),
	}
	if len(got) != len(want) {
		t.Fatalf("sent %d frames, want %d: %q", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("frame %d = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestSelectSamePsetDoesNotSendSelectionCommand(t *testing.T) {
	ln := listenLocal(t)
	defer ln.Close()

	frames := make(chan string, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			frames <- ""
			return
		}
		defer conn.Close()
		reader := bufio.NewReader(conn)
		_ = conn.SetDeadline(time.Now().Add(time.Second))
		_, _ = reader.ReadString(0)
		_, _ = conn.Write(frameForTest(t, OpenProtocolProbeRequest{MID: 2, Revision: 1}))

		_ = conn.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
		frame, _ := reader.ReadString(0)
		frames <- frame
	}()

	host, port := splitTCPAddr(t, ln.Addr().String())
	client := NewClient(nil)
	if err := client.ConnectSession(host, port, 500); err != nil {
		t.Fatalf("ConnectSession failed: %v", err)
	}
	defer client.Disconnect()
	client.mu.Lock()
	client.psetSelectionSubscribed = true
	client.selectedPset = "007"
	client.resultSubscribed = true
	client.mu.Unlock()

	if err := client.SelectPsetForStationContext(context.Background(), "7", 2, 500*time.Millisecond); err != nil {
		t.Fatalf("SelectPsetForStationContext failed for current Pset: %v", err)
	}
	if got := <-frames; got != "" {
		t.Fatalf("sent command for already selected Pset: %q", got)
	}
}

func TestSelectPsetStopsWhenSelectionIsRejected(t *testing.T) {
	ln := listenLocal(t)
	defer ln.Close()

	extraFrame := make(chan string, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			extraFrame <- ""
			return
		}
		defer conn.Close()
		reader := bufio.NewReader(conn)
		_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
		_, _ = reader.ReadString(0)
		_, _ = conn.Write(frameForTest(t, OpenProtocolProbeRequest{MID: 2, Revision: 1}))

		_ = readFrameForTest(reader)
		_, _ = conn.Write(commandRejectedFrameForTest(t, 18, "03"))
		_ = conn.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
		frame, _ := reader.ReadString(0)
		extraFrame <- frame
	}()

	host, port := splitTCPAddr(t, ln.Addr().String())
	client := NewClient(nil)
	if err := client.ConnectSession(host, port, 500); err != nil {
		t.Fatalf("ConnectSession failed: %v", err)
	}
	defer client.Disconnect()
	client.mu.Lock()
	client.psetSelectionSubscribed = true
	client.selectedPset = "001"
	client.resultSubscribed = true
	client.mu.Unlock()

	err := client.SelectPsetForStationContext(context.Background(), "7", 2, 500*time.Millisecond)
	if err == nil || !strings.Contains(err.Error(), "0018") || !strings.Contains(err.Error(), "03") {
		t.Fatalf("SelectPsetForStationContext error = %v", err)
	}
	if got := <-extraFrame; got != "" {
		t.Fatalf("sent command after rejected Pset selection: %q", got)
	}
}

func TestSelectPsetCancellationDoesNotSendCleanupCommands(t *testing.T) {
	ln := listenLocal(t)
	defer ln.Close()

	selectionSent := make(chan struct{})
	frames := make(chan []string, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			frames <- nil
			return
		}
		defer conn.Close()
		reader := bufio.NewReader(conn)
		_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
		_, _ = reader.ReadString(0)
		_, _ = conn.Write(frameForTest(t, OpenProtocolProbeRequest{MID: 2, Revision: 1}))

		var got []string
		got = append(got, readFrameForTest(reader))
		close(selectionSent)

		_ = conn.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
		extra, _ := reader.ReadString(0)
		got = append(got, extra)
		frames <- got
	}()

	host, port := splitTCPAddr(t, ln.Addr().String())
	client := NewClient(nil)
	if err := client.ConnectSession(host, port, 500); err != nil {
		t.Fatalf("ConnectSession failed: %v", err)
	}
	defer client.Disconnect()
	client.mu.Lock()
	client.psetSelectionSubscribed = true
	client.selectedPset = "001"
	client.resultSubscribed = true
	client.mu.Unlock()

	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() {
		errCh <- client.SelectPsetForStationContext(ctx, "7", 2, time.Second)
	}()
	<-selectionSent
	cancel()
	if err := <-errCh; !errors.Is(err, context.Canceled) {
		t.Fatalf("SelectPsetForStationContext error = %v, want context cancellation", err)
	}

	got := <-frames
	want := []string{
		string(frameForTest(t, OpenProtocolProbeRequest{MID: 18, Revision: 1, Station: 2, Data: "007"})),
		"",
	}
	if len(got) != len(want) {
		t.Fatalf("sent %d frames, want %d: %q", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("frame %d = %q, want %q", i, got[i], want[i])
		}
	}
}

func frameForTest(t *testing.T, req OpenProtocolProbeRequest) []byte {
	t.Helper()
	frame, err := BuildOpenProtocolFrame(req)
	if err != nil {
		t.Fatal(err)
	}
	return frame
}

func commandAcceptedFrameForTest(t *testing.T, mid int) []byte {
	t.Helper()
	return frameForTest(t, OpenProtocolProbeRequest{MID: 5, Revision: 1, Data: fourDigitMID(mid)})
}

func commandRejectedFrameForTest(t *testing.T, mid int, code string) []byte {
	t.Helper()
	return frameForTest(t, OpenProtocolProbeRequest{MID: 4, Revision: 1, Data: fourDigitMID(mid) + code})
}

func fourDigitMID(mid int) string {
	return fmt.Sprintf("%04d", mid)
}

func readFrameForTest(reader *bufio.Reader) string {
	frame, _ := reader.ReadString(0)
	return frame
}

func listenLocal(t *testing.T) net.Listener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	return ln
}

func splitTCPAddr(t *testing.T, addr string) (string, int) {
	t.Helper()
	host, portText, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatal(err)
	}
	port, err := net.LookupPort("tcp", portText)
	if err != nil {
		t.Fatal(err)
	}
	return host, port
}
