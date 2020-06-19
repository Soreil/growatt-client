package growatt

import (
	"testing"

	"github.com/google/gopacket"

	"github.com/google/gopacket/pcap"
)

func TestNewProcessing(t *testing.T) {
	testFile := `..\dumps\dump-13-27.pcap`
	handle, err := pcap.OpenOffline(testFile)
	if err != nil {
		panic(err)
	}
	defer handle.Close()

	packets := gopacket.NewPacketSource(handle, handle.LinkType())

	output := make(chan TaggedRegister)
	go ReadRegisterPackets(packets.Packets(), output)
	for p := range output {
		t.Log(p.Registers)
	}

}
func TestNewProcessingV6(t *testing.T) {
	testFile := `..\dumps\packets.pcap`
	handle, err := pcap.OpenOffline(testFile)
	if err != nil {
		panic(err)
	}
	defer handle.Close()

	packets := gopacket.NewPacketSource(handle, handle.LinkType())

	output := make(chan TaggedRegister)
	go ReadRegisterPackets(packets.Packets(), output)
	for p := range output {
		t.Log(p.Registers)
	}

}

func TestCapture19062020(t *testing.T) {
	testFile := `..\dumps\packets.pcap`

	handle, err := pcap.OpenOffline(testFile)
	if err != nil {
		panic(err)
	}
	defer handle.Close()

	packets := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packets.Packets() {
		if packet, err := readModbus(packet); err != nil {
			t.Log(err)
		} else {
			t.Logf("%+v\n", packet)
		}
	}

}

func TestModbus(t *testing.T) {
	testFile := `..\dumps\dump-13-27.pcap`
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
