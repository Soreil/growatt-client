package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"log"
	"time"

	"github.com/google/gopacket"
)

type growattPacketType uint16

const (
	unknown growattPacketType = iota
	registers
	registersAck
	ping
	pingAck
)

func typeOf(m ModbusTCP) (growattPacketType, error) {
	if m.ProtocolIdentifier != ModbusProtocolGrowattV5 {
		return unknown, errors.New("Unknown protocol:" + m.ProtocolIdentifier.String())
	}

	switch growattType(m.GrowattMessageID) {
	case dataID:
		if m.Length == 217 {
			return registers, nil
		} else if m.Length == 3 {
			return registersAck, nil
		}
		return registers, errors.New("invalid registers length")

	case pingID:
		if m.Length == 12 {
			return ping, nil
		}
		return ping, errors.New("Invalid ping length")

	}

	return unknown, errors.New("Unknown packet identifier")
}

//readRegisteredPackets checks if a packet is a data packet and sends the extracted and timestamped data for output
func readRegisterPackets(pChan <-chan gopacket.Packet, regChan chan<- taggedRegister) {
	const XORKey = "Growatt"

	for packet := range pChan {
		modbus, err := readModbus(packet)
		if err != nil {
			continue
		}

		t, err := typeOf(modbus)
		if err != nil {
			log.Println(err)
			continue
		}

		switch t {
		case registers:
			body := xor(modbus.Payload(), []byte(XORKey))
			regs := readRegStruct(body)
			log.Printf("%+v\n", regs)
			regChan <- taggedRegister{time.Now(), regs}
		case ping:
			body := xor(modbus.Payload(), []byte(XORKey))
			InverterID := string(body[:len(body)-growattPadding])
			log.Printf("%+v\n", InverterID)
		case registersAck:
			body := xor(modbus.Payload(), []byte(XORKey))
			ack := uint8(body[:len(body)-growattPadding][0])
			if ack != 0 {
				log.Println("Server did not ack registers upload correctly:", ack)
			}
		}
		log.Println(modbus.TransactionIdentifier)

	}
}

//Xor will loop around the b key if is is shorter than the a key
func xor(a []byte, b []byte) []byte {
	res := make([]byte, len(a))
	for i := range a {
		res[i] = a[i] ^ b[i%len(b)]
	}
	return res
}

//These types appear to be valid for multiple versions of the protocol
type growattType uint8

const (
	pingID growattType = 0x16
	dataID growattType = 0x04
)

//taggedRegister is a simple helper pair
type taggedRegister struct {
	time.Time
	growattRegisters
}

//These registers might not be complete or correct. The fields we are currently using are correct though
type growattRegisters struct {
	Status    uint16
	Ppv       uint32
	Vpv1      uint16
	Ipv1      uint16
	Ppv1      uint32
	Vpv2      uint16
	Ipv2      uint16
	Ppv2      uint32
	Pac       uint32
	Vac       uint16
	Vac1      uint16
	Iac1      uint16
	Pac1      uint32
	Vac2      uint16
	Iac2      uint16
	Pac2      uint32
	Vac3      uint16
	Iac3      uint16
	Pac3      uint32
	EToday    uint32
	ETotal    uint32
	Tall      uint32
	Tmp       uint16
	ISOF      uint16
	GFCIF     uint16
	DCIF      uint16
	Vpvfault  uint16
	Vacfault  uint16
	Facfault  uint16
	Tmpfault  uint16
	Faultcode uint16
	IPMtemp   uint16
	Pbusvolt  uint16
	Nbusvolt  uint16
	Padding   [12]byte
	Epv1today uint32
	Epv1total uint32
	Epv2today uint32
	Epv2total uint32
	Epvtotal  uint32
	Rac       uint32
	ERactoday uint32
	Eractotal uint32
}

//TODO give this a proper name
func readRegStruct(s []byte) growattRegisters {
	r := bytes.NewReader(s[31:])

	var g growattRegisters
	//TODO in other cases we have littleendian, is this correct at all?
	binary.Read(r, binary.BigEndian, &g)

	return g
}
