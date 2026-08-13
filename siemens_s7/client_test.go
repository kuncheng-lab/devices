package siemens_s7

import (
	"encoding/binary"
	"testing"
)

func TestDBValueHelpersUseS7BigEndian(t *testing.T) {
	buf := make([]byte, 8)
	PutInt32(buf, 0, 0x01020304)
	PutInt16(buf, 4, 0x0506)
	buf[6] = 0b00001010

	if got := Int32At(buf, 0); got != 0x01020304 {
		t.Fatalf("Int32At = 0x%X", got)
	}
	if got := Int16At(buf, 4); got != 0x0506 {
		t.Fatalf("Int16At = 0x%X", got)
	}
	if !BoolAt(buf, 6, 1) {
		t.Fatal("BoolAt bit 1 = false")
	}
	if BoolAt(buf, 6, 0) {
		t.Fatal("BoolAt bit 0 = true")
	}
}

func TestBuildS7DBBitWriteRequestMatchesHSLPacket(t *testing.T) {
	request, err := buildS7DBBitWriteRequest(1, 101, 4, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(request) != 36 || binary.BigEndian.Uint16(request[2:4]) != 36 {
		t.Fatalf("request length=%d TPKT=%d", len(request), binary.BigEndian.Uint16(request[2:4]))
	}
	if request[17] != 0x05 || request[21] != 0x10 || request[22] != 0x01 {
		t.Fatalf("unexpected write function/transport: % X", request[17:23])
	}
	if got := binary.BigEndian.Uint16(request[25:27]); got != 1 || request[27] != 0x84 {
		t.Fatalf("DB/area=%d/0x%02X", got, request[27])
	}
	wantAddress := 101*8 + 4
	gotAddress := int(request[28])<<16 | int(request[29])<<8 | int(request[30])
	if gotAddress != wantAddress {
		t.Fatalf("bit address=%d, want %d", gotAddress, wantAddress)
	}
	if request[32] != 0x03 || binary.BigEndian.Uint16(request[33:35]) != 1 || request[35] != 1 {
		t.Fatalf("unexpected bit payload: % X", request[31:])
	}

	request, err = buildS7DBBitWriteRequest(1, 100, 2, false)
	if err != nil {
		t.Fatal(err)
	}
	if request[35] != 0 {
		t.Fatalf("false payload=%d", request[35])
	}
}

func TestBuildS7DBBitWriteRequestRejectsInvalidAddress(t *testing.T) {
	for _, tc := range []struct{ db, offset, bit int }{
		{-1, 0, 0}, {65536, 0, 0}, {1, -1, 0}, {1, 0, -1}, {1, 0, 8}, {1, 1 << 21, 0},
	} {
		if _, err := buildS7DBBitWriteRequest(tc.db, tc.offset, tc.bit, true); err == nil {
			t.Fatalf("address %+v accepted", tc)
		}
	}
}

func TestParseS7WriteResponse(t *testing.T) {
	response := []byte{
		0x03, 0x00, 0x00, 0x16, 0x02, 0xf0, 0x80,
		0x32, 0x03, 0x00, 0x00, 0x00, 0x01, 0x00, 0x02, 0x00, 0x01,
		0x00, 0x00, 0x05, 0x01, 0xff,
	}
	if err := parseS7WriteResponse(response); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func([]byte){
		"item rejected": func(b []byte) { b[21] = 0x05 },
		"CPU error":     func(b []byte) { b[18] = 0x01 },
		"wrong length":  func(b []byte) { b[3] = 0x15 },
	} {
		t.Run(name, func(t *testing.T) {
			invalid := append([]byte(nil), response...)
			mutate(invalid)
			if err := parseS7WriteResponse(invalid); err == nil {
				t.Fatal("invalid response accepted")
			}
		})
	}
}
