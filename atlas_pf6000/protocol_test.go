package atlas_pf6000

import (
	"bufio"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestBuildOpenProtocolFrame(t *testing.T) {
	frame, err := BuildOpenProtocolFrame(OpenProtocolProbeRequest{
		MID:      1,
		Revision: 0,
		Station:  0,
		Spindle:  1,
	})
	if err != nil {
		t.Fatal(err)
	}
	got := string(frame)
	want := "002000010000   100  \x00"
	if got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestBuildOpenProtocolFrameWithData(t *testing.T) {
	frame, err := BuildOpenProtocolFrame(OpenProtocolProbeRequest{
		MID:      18,
		Revision: 0,
		Station:  0,
		Spindle:  1,
		Data:     "001",
	})
	if err != nil {
		t.Fatal(err)
	}
	got := string(frame)
	want := "002300180000   100  001\x00"
	if got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestParseSelectedPset(t *testing.T) {
	tests := []struct {
		name string
		msg  OpenProtocolMessage
		want string
	}{
		{name: "revision 1", msg: OpenProtocolMessage{MID: "0015", Revision: "001", Data: "0072026-07-20:12:00:00"}, want: "007"},
		{name: "revision 2", msg: OpenProtocolMessage{MID: "0015", Revision: "002", Data: "0100702Example"}, want: "007"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, ok := ParseSelectedPset(test.msg)
			if !ok || got != test.want {
				t.Fatalf("ParseSelectedPset() = %q, %v, want %q, true", got, ok, test.want)
			}
		})
	}
}

func TestSummarizeModeList(t *testing.T) {
	msg := OpenProtocolMessage{MID: "2601", Data: "002000104Test001203ABC"}
	got := SummarizeOpenProtocolResponse(msg)
	for _, want := range []string{"共 2 个", "Mode 0001: Test", "Mode 0012: ABC"} {
		if !strings.Contains(got, want) {
			t.Fatalf("summary %q does not contain %q", got, want)
		}
	}
}

func TestSummarizeModeDetail(t *testing.T) {
	msg := OpenProtocolMessage{MID: "2603", Data: "000105Mode1002007001000105BoltA012002000204Bolt"}
	got := SummarizeOpenProtocolResponse(msg)
	for _, want := range []string{"Mode ID: 0001", "名称: Mode1", "Bolt 数量: 2", "Bolt 0001: Pset 007，Tool 001，BoltA", "Bolt 0002: Pset 012，Tool 002，Bolt"} {
		if !strings.Contains(got, want) {
			t.Fatalf("summary %q does not contain %q", got, want)
		}
	}
}

func TestBuildOpenProtocolFrameStrictHeader(t *testing.T) {
	frame, err := BuildOpenProtocolFrame(OpenProtocolProbeRequest{
		MID:          10,
		Revision:     1,
		StrictHeader: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	got := string(frame)
	want := "00200010001000000000\x00"
	if got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestSummarizeOpenProtocolAccepted(t *testing.T) {
	msg, err := ParseOpenProtocolMessage("002400050000000000000018")
	if err != nil {
		t.Fatal(err)
	}
	if got := SummarizeOpenProtocolResponse(msg); !strings.Contains(got, "0018") {
		t.Fatalf("summary did not mention accepted MID: %q", got)
	}
}

func TestSummarizeOpenProtocolError(t *testing.T) {
	msg, err := ParseOpenProtocolMessage("00260004000000000000250599")
	if err != nil {
		t.Fatal(err)
	}
	got := SummarizeOpenProtocolResponse(msg)
	if !strings.Contains(got, "2505") || !strings.Contains(got, "Unknown MID") {
		t.Fatalf("unexpected summary: %q", got)
	}
}

func TestSummarizePsetList(t *testing.T) {
	msg := OpenProtocolMessage{MID: "0011", Data: "03001002012"}
	got := SummarizeOpenProtocolResponse(msg)
	for _, want := range []string{"001", "002", "012"} {
		if !strings.Contains(got, want) {
			t.Fatalf("summary %q did not contain pset %s", got, want)
		}
	}
}

func TestSummarizePsetListWithThreeDigitCount(t *testing.T) {
	msg := OpenProtocolMessage{MID: "0011", Data: "003001002012"}
	got := SummarizeOpenProtocolResponse(msg)
	for _, want := range []string{"001", "002", "012"} {
		if !strings.Contains(got, want) {
			t.Fatalf("summary %q did not contain pset %s", got, want)
		}
	}
}

func TestSummarizePsetListWithRevisionExtras(t *testing.T) {
	msg := OpenProtocolMessage{MID: "0011", Data: "0020010020102PsetMset2026-06-24:10:11:122026-06-24:10:12:13"}
	got := SummarizeOpenProtocolResponse(msg)
	for _, want := range []string{"步骤数=01", "步骤数=02", "类型=Pset", "类型=Mset", "2026-06-24:10:11:12", "2026-06-24:10:12:13"} {
		if !strings.Contains(got, want) {
			t.Fatalf("summary %q did not contain %q", got, want)
		}
	}
}

func TestSummarizePsetDetail(t *testing.T) {
	data := "" +
		"01001" +
		"02P2 RIGHT                 " +
		"031" +
		"0402" +
		"05004500" +
		"06006700" +
		"07005500" +
		"0800180" +
		"0900360" +
		"1000270" +
		"11005000" +
		"12000090" +
		"132026-06-24:10:11:12"
	msg := OpenProtocolMessage{MID: "0013", Data: data}
	got := SummarizeOpenProtocolResponse(msg)
	for _, want := range []string{"Pset ID: 001", "P2 RIGHT", "CW", "45.00 Nm", "55.00 Nm", "67.00 Nm", "180 deg", "270 deg", "360 deg", "50.00 Nm", "0.90 deg", "2026-06-24:10:11:12"} {
		if !strings.Contains(got, want) {
			t.Fatalf("summary %q did not contain %q", got, want)
		}
	}
}

func TestSummarizeTighteningResult(t *testing.T) {
	msg := sampleTighteningResultMessage()
	got := SummarizeOpenProtocolResponse(msg)
	for _, want := range []string{"Pset ID: 007", "VIN001", "OK", "5.23 Nm", "178 deg", "0000000123"} {
		if !strings.Contains(got, want) {
			t.Fatalf("summary %q did not contain %q", got, want)
		}
	}
}

func TestParseTighteningResult(t *testing.T) {
	msg := sampleTighteningResultMessage()
	result, ok := ParseTighteningResult(msg)
	if !ok {
		t.Fatal("ParseTighteningResult did not parse sample")
	}
	if !result.OK() {
		t.Fatalf("result.OK() = false, want true")
	}
	if result.PsetID != "007" || result.TorqueActual != "5.23 Nm" || result.AngleActual != "178 deg" || result.TighteningID != "0000000123" {
		t.Fatalf("unexpected parsed result: %+v", result)
	}
	if result.HeaderSpindle != "01" {
		t.Fatalf("HeaderSpindle = %q, want 01", result.HeaderSpindle)
	}
}

func TestParseMultiSpindleResult(t *testing.T) {
	msg := OpenProtocolMessage{
		MID:      "0101",
		Revision: "001",
		Station:  "  ",
		Spindle:  "  ",
		Data: "010202                         " +
			"030204002050000060000072080000000999999910000000110000012099991300000" +
			"142026-06-26:08:26:47152026-06-26:08:26:47164557917118010111006645100890020211006635100655",
	}
	results, ok := ParseMultiSpindleResult(msg)
	if !ok {
		t.Fatal("ParseMultiSpindleResult returned false")
	}
	if len(results) != 2 {
		t.Fatalf("len(results) = %d, want 2", len(results))
	}
	first := results[0]
	if first.PsetID != "002" || first.HeaderSpindle != "01" || first.ChannelID != "01" {
		t.Fatalf("first identity = pset %q spindle %q channel %q", first.PsetID, first.HeaderSpindle, first.ChannelID)
	}
	if !first.OK() || first.TorqueActual != "66.45 Nm" || first.AngleActual != "890 deg" {
		t.Fatalf("first result = ok %v torque %q angle %q", first.OK(), first.TorqueActual, first.AngleActual)
	}
	second := results[1]
	if second.HeaderSpindle != "02" || second.ChannelID != "02" {
		t.Fatalf("second identity = spindle %q channel %q", second.HeaderSpindle, second.ChannelID)
	}
	if !second.OK() || second.TorqueActual != "66.35 Nm" || second.AngleActual != "655 deg" {
		t.Fatalf("second result = ok %v torque %q angle %q", second.OK(), second.TorqueActual, second.AngleActual)
	}
	if first.TighteningID == second.TighteningID {
		t.Fatalf("per-spindle tightening IDs should differ, got %q", first.TighteningID)
	}
}

func TestParseMultiSpindleNOKResult(t *testing.T) {
	msg := OpenProtocolMessage{
		MID:      "0101",
		Revision: "001",
		Station:  "  ",
		Spindle:  "  ",
		Data: "010202                         " +
			"030204002050000060000072080000000999999910000000110000012099991300000" +
			"142026-06-26:08:26:44152026-06-26:08:26:44164557817018010101000280106074020201000301106080",
	}
	results, ok := ParseMultiSpindleResult(msg)
	if !ok {
		t.Fatal("ParseMultiSpindleResult returned false")
	}
	if len(results) != 2 {
		t.Fatalf("len(results) = %d, want 2", len(results))
	}
	first := results[0]
	if first.OK() || first.TighteningStatus != "0" || first.TorqueActual != "2.80 Nm" || first.AngleActual != "6074 deg" {
		t.Fatalf("first NOK result = ok %v status %q torque %q angle %q", first.OK(), first.TighteningStatus, first.TorqueActual, first.AngleActual)
	}
	second := results[1]
	if second.OK() || second.TighteningStatus != "0" || second.TorqueActual != "3.01 Nm" || second.AngleActual != "6080 deg" {
		t.Fatalf("second NOK result = ok %v status %q torque %q angle %q", second.OK(), second.TighteningStatus, second.TorqueActual, second.AngleActual)
	}
}

func sampleTighteningResultMessage() OpenProtocolMessage {
	data := "" +
		"010001" +
		"0201" +
		"03PF6000                   " +
		"04VIN001                   " +
		"0501" +
		"06007" +
		"070004" +
		"080001" +
		"091" +
		"101" +
		"111" +
		"12000450" +
		"13000550" +
		"14000500" +
		"15000523" +
		"1600100" +
		"1700300" +
		"1800180" +
		"1900178" +
		"202026-06-24:14:30:00" +
		"212026-06-24:14:00:00" +
		"221" +
		"230000000123"
	return OpenProtocolMessage{MID: "0061", Spindle: "01", Data: data}
}

func TestProbeOpenProtocol(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	done := make(chan string, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			done <- ""
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(time.Second))
		tx, _ := bufio.NewReader(conn).ReadString(0)
		done <- tx
		_, _ = conn.Write([]byte("002400050000000000000001\x00"))
	}()

	host, portText, err := net.SplitHostPort(ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		t.Fatal(err)
	}
	result, err := ProbeOpenProtocol(OpenProtocolProbeRequest{
		Host:      host,
		Port:      port,
		MID:       1,
		Spindle:   1,
		TimeoutMs: 500,
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := <-done; got != "002000010000   100  \x00" {
		t.Fatalf("server got %q", got)
	}
	if result.MID != "0005" || !strings.Contains(result.Summary, "0001") {
		t.Fatalf("unexpected probe result: %+v", result)
	}
}
