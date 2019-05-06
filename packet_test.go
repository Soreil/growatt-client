package main

import (
	"testing"
	"time"
)

//TODO rewrite
func NoTestUpload(t *testing.T) {
	//NOTE do not leave baseURL set to PVOutput or you will pollute your monitoring data.

	var fields growatt.GrowattRegisters
	fields.Ppv = 100   //10W
	fields.Tmp = 230   //23C
	fields.Vac1 = 2351 //235.1V

	tim := time.Now()

	err := upload(growatt.TaggedRegister{tim,
		fields})
	if err != nil {
		t.Fatal(err)
	}
}
