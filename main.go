package main

import (
	"flag"
	"fmt"
	"log"
	"time"

	"github.com/google/gopacket"
	"github.com/vharitonsky/iniflags"

	"github.com/google/gopacket/pcap"
)

var (
	port     = flag.Int("port", 5279, "Port number")
	network  = flag.String("interface", "wlan0", "Network interface")
	hostname = flag.String("hostname", "", "Hostname of dongle")
	module   = flag.String("dongle", "", "ID of the dongle")
	inverter = flag.String("inverter", "", "ID of the inverter")
	apiKey   = flag.String("pvoutkey", "", "PVoutput API key, needs to be read write")
	systemID = flag.Int("pvoutid", 0, "PVoutput system ID")
	baseURL  = flag.String("dest", `https://pvoutput.org/service/r2/addstatus.jsp`, "API endpoint URL for live updates")
)

func main() {
	iniflags.Parse()

	//TODO make it so the program can run without pvout enabled
	if *hostname == "" {
		log.Fatalln("hostname not set")
	}
	if *module == "" {
		log.Fatalln("dongle not set")
	}
	if *inverter == "" {
		log.Fatalln("Inverter not set")
	}
	if *apiKey == "" {
		log.Fatalln("pvoutkey not set")
	}
	if *systemID == 0 {
		log.Fatalln("pvoutid not set")
	}

	//TODO: Allow choosing the interface to listen on
	handle, err := pcap.OpenLive(*network, int32(0xffff), false, -1*time.Second)
	if err != nil {
		panic(err)
	}
	defer handle.Close()

	//TODO: Maybe allow choosing port number optionally
	err = handle.SetBPFFilter("tcp and port " + fmt.Sprint(*port) + " and host " + *hostname)
	if err != nil {
		panic(err)
	}

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	statusUpdates := make(chan taggedRegister)
	go readRegisterPackets(packetSource.Packets(), statusUpdates)

	//TODO: allow choosing a different duration in case we want slower reports or find a way to query the dongle faster
	ticker := time.NewTicker(time.Minute * 5)

	var readyStatusses []taggedRegister
	for {
		select {
		case status := <-statusUpdates:
			readyStatusses = append(readyStatusses, status)
		case <-ticker.C:
			//TODO: could we instead wait on a status here? The other case in the outer select statement
			//can't fire while we are still in the current case. Would this cause any issues?
			if len(readyStatusses) == 0 {
				break
			}
			//TODO: Do we want the most recent statement or the oldest unuploaded statement?
			err := upload(readyStatusses[len(readyStatusses)-1])
			if err != nil {
				//TODO: We might want to simply log a failed upload, we should be handling things like rate limiting
				//notices we get
				log.Println(err)
			}
			//TODO: Don't throw away unuploaded statusses, we can use these for our end of day report
			readyStatusses = readyStatusses[:0]
		}
	}
}
