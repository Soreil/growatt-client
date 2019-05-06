package main

import (
	"fmt"
	"io/ioutil"
	"log"
	"net/http"

	"github.com/soreil/growatt-client/growatt"
)

//Uploads the packet Time, Wattage, Temperature and Voltage to PVOutput
func upload(status growatt.TaggedRegister) error {
	var client http.Client

	req, err := http.NewRequest("POST", *baseURL, nil)
	if err != nil {
		log.Println(err)
	}

	req.Header.Add("X-Pvoutput-Apikey", *apiKey)
	req.Header.Add("X-Pvoutput-SystemId", fmt.Sprint(*systemID))

	q := req.URL.Query()

	y, m, d := status.Time.Date()
	h, min, _ := status.Time.Clock()
	date := fmt.Sprintf("%4d%2d%2d", y, m, d)
	clock := fmt.Sprintf("%2d:%2d", h, min)

	//These are all the free PVOutput features we can use reliably.
	q.Add("d", date)
	q.Add("t", clock)
	q.Add("v2", fmt.Sprint((status.growattRegisters.Ppv)/10))
	q.Add("v5", fmt.Sprint(float32(status.growattRegisters.Tmp)/10))
	q.Add("v6", fmt.Sprint(float32(status.growattRegisters.Vac1)/10))

	req.URL.RawQuery = q.Encode()

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := ioutil.ReadAll(resp.Body)
		//This should give us a detailed error in the case of a 400 code
		log.Println(string(body))
		log.Printf("%+v\n", resp)
	}

	return nil
}
