package main

import (
	"errors"

	"github.com/google/gopacket"
)

func readModbus(packet gopacket.Packet) (ModbusTCP, error) {
	var modbus ModbusTCP
	app := packet.ApplicationLayer()
	if app == nil {
		return modbus, errors.New("No application layer in packet")
	}

	buf := app.LayerContents()

	if buf != nil {
		var feedback = gopacket.NilDecodeFeedback

		err := modbus.DecodeFromBytes(buf, feedback)
		if err != nil {
			return modbus, err
		}
	} else {
		return modbus, errors.New("Failed to read application layer body")
	}
	return modbus, nil

}
