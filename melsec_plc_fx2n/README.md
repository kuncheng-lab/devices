# Mitsubishi FX2N serial client

This package implements two serial protocols for FX2N PLCs such as
`FX2N-32MT`:

- `computer_link`: MELSEC-A-compatible Computer Link format 1 for an
  `FX2N-485-BD`/485 adapter;
- `programming_port`: the round programming-port protocol used through an
  SC-09/USB-SC09 cable.

It supports the addresses needed by the fill-oil application:

- packed 16-bit reads from `X0` and `Y0`;
- word reads and writes for `D0` through `D511` and `D8000` through `D8255`;
- packed 16-bit reads from `M` and `S` devices.

Example:

```go
plc := melsec_plc_fx2n.New(melsec_plc_fx2n.Config{
    Protocol:    melsec_plc_fx2n.ProtocolComputerLink,
    Port:        "COM6",
    Baud:        9600,
    DataBits:    7,
    Parity:      "E",
    StopBits:    1,
    Station:     0,
    MessageWait: 0,
    TimeoutMs:   1000,
})
defer plc.Close()

x, err := plc.ReadWord("X0")
err = plc.WriteWord("D2", 10)
```

The PLC model alone does not determine all serial settings. Before deployment,
inspect logical station `1` in the Mitsubishi MX Component Communication Setup
Utility on the old industrial PC. Copy its protocol, COM port, baud rate, data
bits, parity, stop bits, station number and sum-check setting into the Go
application configuration.

`computer_link` uses `WR` for packed X/Y reads and D-register reads, and `WW`
for D-register writes. X/Y device addresses are encoded in octal. The request
and response framing follows Mitsubishi's FX data communication manual,
including station number, PLC number `FF`, ACK/NAK and optional sum check.
