package main

import (
	"testing"

	"github.com/google/gopacket"

	"github.com/google/gopacket/pcap"
)

func TestNewProcessing(t *testing.T) {
	testFile := `dumps\dump-13-27.pcap`
	handle, err := pcap.OpenOffline(testFile)
	if err != nil {
		panic(err)
	}
	defer handle.Close()

	packets := gopacket.NewPacketSource(handle, handle.LinkType())

	output := make(chan taggedRegister)
	go readRegisterPackets(packets.Packets(), output)
	for p := range output {
		t.Log(p.growattRegisters)
	}

}

func TestModbus(t *testing.T) {
	testFile := `dumps\dump-13-27.pcap`
	handle, err := pcap.OpenOffline(testFile)
	if err != nil {
		panic(err)
	}
	defer handle.Close()

	packets := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packets.Packets() {
		if packet, err := readModbus(packet); err != nil {
			t.Error(err)
		} else {
			t.Logf("%+v\n", packet)
		}
	}

}
