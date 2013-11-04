
package main

import (
	"log"
	"net"
	"os"
	"io"
	_ "io/ioutil"
	"bufio"
	"strings"
	"fmt"
	"bytes"
	"flag"
	"time"
	"encoding/hex"
	"encoding/binary"
	"os/exec"
	"code.google.com/p/gopacket/pcap"
	"code.google.com/p/gopacket/layers"
	"code.google.com/p/gopacket"
)

func findMyIpAndMac() (ip net.IP, mac net.HardwareAddr) {
	var b bytes.Buffer
	cmd := exec.Command("ip", "addr", "show", gwiface)
	cmd.Stdout = &b
	cmd.Run()

	br := bufio.NewReader(&b)
	for {
		l, e := br.ReadString('\n')
		if e != nil {
			break
		}
		f := strings.Fields(l)
		if len(f) < 2 {
			continue
		}
		if f[0] == "link/ether" {
			mac, _ = net.ParseMAC(f[1])
		}
		if f[0] == "inet" {
			if i := strings.Index(f[1], "/"); i > 0 {
				ip = make(net.IP, 4)
				fmt.Sscanf(f[1][:i], "%d.%d.%d.%d", &ip[0], &ip[1], &ip[2], &ip[3])
			}
		}
	}

	if ip == nil {
		panic("myip not found")
	}
	if len(mac) == 0 {
		panic("mymac not found")
	}

	return
}

func findGateway() (iface string, ip net.IP, mac net.HardwareAddr) {
	if f, err := os.Open("/proc/net/route"); err != nil {
		panic(err)
	} else {
		defer f.Close()
		br := bufio.NewReader(f)
		for {
			l, e := br.ReadString('\n')
			if e != nil {
				break
			}
			f := strings.Fields(l)
			if f[1] == "00000000" {
				iface = f[0]
				b1, _ := hex.DecodeString(f[2])
				ip = net.IP{b1[3], b1[2], b1[1], b1[0]}
				break
			}
		}
	}

	if iface == "" {
		panic("default route not found")
	}
	ping := exec.Command("ping", "-c", "1", fmt.Sprint(ip))
	ping.Run()

	if f, err := os.Open("/proc/net/arp"); err != nil {
		panic(err)
	} else {
		defer f.Close()
		br := bufio.NewReader(f)
		for {
			l, e := br.ReadString('\n')
			if e != nil {
				break
			}
			f := strings.Fields(l)
			if f[0] == fmt.Sprint(ip) {
				mac, _ = net.ParseMAC(f[3])
				break
			}
		}
	}

	if len(mac) == 0 {
		panic("cannot find mac of: " + fmt.Sprint(ip))
	}

	return
}

type Packet struct {
	eth *layers.Ethernet
	ip *layers.IPv4
	tcp *layers.TCP
	data []byte
}

func (p Packet) String() string {
	return fmt.Sprintf("%v:%d -> %v:%d %d bytes", p.ip.SrcIP, p.tcp.SrcPort, p.ip.DstIP, p.tcp.DstPort, len(p.data))
}

func WritePkt(w io.Writer, pkt []byte) (err error) {
	if w == nil {
		return
	}
	l := uint16(len(pkt))
	binary.Write(w, binary.BigEndian, l)
	_, err = w.Write(pkt)
	return
}

func UpdatePkt(p *Packet) {
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		ComputeChecksums: true,
		FixLengths: true,
	}
	p.tcp.SetNetworkLayerForChecksum(p.ip)
	p.tcp.SerializeTo(buf, opts)
	p.ip.SerializeTo(buf, opts)
	p.eth.SerializeTo(buf, opts)
	p.data = buf.Bytes()
}

func NewPkt(pbuf []byte) (p Packet, ok bool) {
	pkt := gopacket.NewPacket(pbuf, layers.LinkTypeEthernet, gopacket.Default)
	tcpLayer := pkt.Layer(layers.LayerTypeTCP)
	p.tcp, _ = tcpLayer.(*layers.TCP)
	ipLayer := pkt.Layer(layers.LayerTypeIPv4)
	p.ip, _ = ipLayer.(*layers.IPv4)
	ethLayer := pkt.Layer(layers.LayerTypeEthernet)
	p.eth, _ = ethLayer.(*layers.Ethernet)
	if !(p.tcp == nil || p.ip == nil || p.eth == nil) {
		ok = true
	}
	p.data = pkt.Data()
	return
}

func ConnLoop(conn net.Conn, cb func (pkt Packet)) {
	var l uint16
	var buf [1600]byte
	for {
		if err := binary.Read(conn, binary.BigEndian, &l); err != nil{
			break
		}
		if l > 1600 {
			break
		}
		pbuf := buf[:int(l)]
		if _, err := conn.Read(pbuf); err != nil {
			break
		}
		if p, ok := NewPkt(pbuf); ok {
			cb(p)
		}
	}
	log.Println("Close")
	conn.Close()
}

func openLiveHandle() (handle *pcap.Handle) {
	var err error
	if handle, err = pcap.OpenLive(gwiface, 1600, true, 0); err != nil {
		panic(err)
	}
	log.Println("Pcap", gwiface, "opened")
	if gfilter != "" {
		log.Println("BPFFilter", gfilter)
		if err = handle.SetBPFFilter(gfilter); err != nil {
			panic(err)
		}
	}
	return
}

func nextPkt(h *pcap.Handle) (p Packet) {
	for {
		pbuf, _, err := h.ReadPacketData()
		if err != nil {
			panic(err)
		}
		var ok bool
		if p, ok = NewPkt(pbuf); ok {
			return
		}
	}
	return
}

type TunnelClient struct {
}

func (t TunnelClient) Run() {
	live := openLiveHandle()

	log.Println("Client starts")

	var conn net.Conn

	doOut := func (p Packet) {
		if bytes.Compare(p.eth.DstMAC, mymac) != 0 {
			return
		}
		if myip.Equal(p.ip.DstIP) {
			return
		}
		log.Println(">>>", p)
		WritePkt(conn, p.data)
	}

	doIn := func (p Packet) {
		log.Println("<<<", p)
		live.WritePacketData(p.data)
	}

	go func () {
		var err error
		for {
			host := fmt.Sprintf("%s:%d", ghost, gport)
			log.Println("Connecting", host)
			conn, err = net.DialTimeout("tcp4", host, time.Second*10)
			if err != nil {
				log.Println(err)
				time.Sleep(time.Second)
				continue
			}
			log.Println("Connected", ghost)
			ConnLoop(conn, doIn)
			conn = nil
		}
	}()

	for {
		doOut(nextPkt(live))
	}
}

type natConn struct {
	Ts time.Time
	SrcPort layers.TCPPort
	SrcIP net.IP
	SrcMAC, DstMAC net.HardwareAddr
}

type Nat struct {
	table map[layers.TCPPort]*natConn
}

func NewNat() *Nat {
	t := &Nat{}
	t.table = map[layers.TCPPort]*natConn{}
	return t
}

func (t *Nat) Hash(ip *layers.IPv4, tcp *layers.TCP) (h uint16) {
	h += 3*uint16(ip.SrcIP[0]) + 23*uint16(ip.SrcIP[1]) +
			 13*uint16(ip.SrcIP[2]) + 31*uint16(ip.SrcIP[3])
	h += 13*uint16(ip.DstIP[0]) + 31*uint16(ip.DstIP[1]) +
			 3*uint16(ip.DstIP[2]) + 23*uint16(ip.DstIP[3])
	h += 37*uint16(tcp.SrcPort)
	return
}

func (t *Nat) Out(p Packet) (b []byte) {
	k := p.tcp.DstPort
	c, _ := t.table[k]
	if c == nil {
		return
	}

	log.Println("wire <<<", p)

	p.eth.SrcMAC = c.DstMAC
	p.eth.DstMAC = c.SrcMAC

	p.ip.DstIP = c.SrcIP
	p.tcp.DstPort = c.SrcPort

	if p.tcp.FIN || p.tcp.RST {
		log.Println("nat del", k)
		delete(t.table, k)
	} else {
		c.Ts = time.Now()
	}

	UpdatePkt(&p)

	log.Println("socket >>>", p)

	return p.data
}

func (t *Nat) In(p Packet) (b []byte) {
	//ioutil.WriteFile("/tmp/b.pkt", pkt.Data(), 0777)

	h := layers.TCPPort(t.Hash(p.ip, p.tcp))
	c, _ := t.table[h]
	if p.tcp.SYN && c == nil {
		log.Println("nat new", h)
		c = &natConn{
			Ts: time.Now(),
			SrcPort: p.tcp.SrcPort,
			SrcIP: p.ip.SrcIP,
			SrcMAC: p.eth.SrcMAC,
			DstMAC: p.eth.DstMAC,
		}
		t.table[h] = c
	}

	log.Println("socket <<<", p)

	p.ip.SrcIP = myip
	p.eth.SrcMAC = mymac
	p.eth.DstMAC = gwmac
	p.tcp.SrcPort = h

	UpdatePkt(&p)
	log.Println("wire >>>", p)

	return p.data
}

func (t *Nat) Gc() {
}

type TunnelServer struct {
}

func (t TunnelServer) Run() {
	live := openLiveHandle()

	ln, err := net.Listen("tcp4", fmt.Sprintf(":%d", gport))
	if err != nil {
		panic(err)
	}
	log.Println("Server starts: listening", gport)

	var conn net.Conn

	nat := NewNat()

	doIn := func (pkt Packet) {
		if b := nat.In(pkt); len(b) > 0 {
			live.WritePacketData(b)
		}
	}

	doOut := func (pkt Packet) {
		if b := nat.Out(pkt); len(b) > 0 {
			WritePkt(conn, b)
		}
	}

	go func () {
		var err error
		for {
			conn, err = ln.Accept()
			if err != nil {
				log.Println(err)
				continue
			}
			log.Println("Accepted from", conn.RemoteAddr())
			ConnLoop(conn, doIn)
			conn = nil
		}
	}()

	for {
		doOut(nextPkt(live))
	}
}

var (
	gwiface string
	gwip net.IP
	gwmac net.HardwareAddr
	myip net.IP
	mymac net.HardwareAddr
	gfilter string //"dst net 95.138.148.0 mask 255.255.255.0"
	gport int
	ghost string
)

func main() {
	// "106.187.99.23:1988"

	var test bool
	flag.StringVar(&ghost, "h", "", "tunnel server host ip")
	flag.IntVar(&gport, "p", 9998, "tunnel server listen port")
	flag.StringVar(&gfilter, "f", "", "tunnel pcap filter")
	flag.BoolVar(&test, "t", false, "test")
	flag.Parse()

	gwiface, gwip, gwmac = findGateway()
	log.Println("Found gateway", gwiface, gwip, gwmac)

	myip, mymac = findMyIpAndMac()
	log.Println("Found my ip", myip, "mac", mymac)

	if test {
		return
	}

	if ghost == "" {
		srv := TunnelServer{}
		srv.Run()
	} else {
		cli := TunnelClient{}
		cli.Run()
	}
}

