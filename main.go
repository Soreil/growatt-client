package main

import (
	"bytes"
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
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

//Uploads the packet Time, Wattage, Temperature and Voltage to PVOutput
func upload(status taggedRegister) error {
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

//readRegisteredPackets checks if a packet is a data packet and sends the extracted and timestamped data for output
func readRegisterPackets(pChan <-chan gopacket.Packet, regChan chan<- taggedRegister) {

	for packet := range pChan {

		transLayer := packet.ApplicationLayer()
		if transLayer == nil {
			continue
		}
		transLayer.LayerContents()

		r := bytes.NewReader(transLayer.LayerContents())
		msg := identifyMessage(r)

		if isDataPacket(msg) {
			body := msg.readDataBody(r)
			decoded := xor(body.Tail[:], []byte("Growatt"))

			r = bytes.NewReader(decoded)
			regs := read(r)

			log.Printf("%s\n%+v\n", time.Now(), regs)

			regChan <- taggedRegister{time.Now(), regs}
		}
	}
}

//We require the length since the data packet ack uses the same type
func isDataPacket(msg growattHeader) bool {
	return msg.Length == 217 && msg.Typ == data && msg.Version == 5
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
type growattType uint16

const (
	ping growattType = 278
	data growattType = 260
)

//This seems to be a universal standard for growatt protocol versions
const headerSize = 8

//Some older versions of the growatt protocol seem to have a 4 byte version instead of 2 bytes for index and version
//These protocol versions lack an index
type growattHeader struct {
	Index   uint16
	Version uint16
	Length  uint16
	Typ     growattType
}

//TODO we don't know what the tail is used for
type pingMessage struct {
	Key  [10]byte
	Tail [2]byte
}

//TODO we don't know what the tail is used for of course ACK is 3 letters but it doesn't seem to match
type dataAck struct {
	Tail [3]byte
}

//TODO should we put the growattregisters struct straight in here?
type dataBody struct {
	Tail [217]byte
}

func (body dataBody) readRegisters() growattRegisters {
	decoded := xor(body.Tail[:], []byte("Growatt"))
	r := bytes.NewReader(decoded)
	regs := read(r)

	return regs
}

//Extract data from the packet
func (g growattHeader) readDataAck(r io.ReadSeeker) dataAck {
	var body dataAck
	r.Seek(8, 0)
	binary.Read(r, binary.LittleEndian, &body)
	return body
}

//Extract data from the packet
func (g growattHeader) readDataBody(r io.ReadSeeker) dataBody {
	var body dataBody
	r.Seek(8, 0)
	binary.Read(r, binary.LittleEndian, &body)
	return body
}

func (g growattHeader) readPing(r io.ReadSeeker) pingMessage {
	var body pingMessage
	r.Seek(8, 0)
	binary.Read(r, binary.LittleEndian, &body)
	decoded := xor(body.Key[:], []byte("GrowattGro"))
	copy(body.Key[:], decoded)

	return body
}

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
func read(r io.ReadSeeker) growattRegisters {

	r.Seek(10+10+11, 0) //inverter + dongle + padding
	var g growattRegisters
	//TODO in other cases we have littleendian, is this correct at all?
	binary.Read(r, binary.BigEndian, &g)

	return g
}

//Read the message header in to a growattheader struct
func identifyMessage(r io.Reader) (g growattHeader) {
	//TODO in other cases we have littleendian, is this correct at all?
	binary.Read(r, binary.BigEndian, &g)
	return
}
