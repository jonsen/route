
package main

import (
	"log"
	"net"
	"os"
	"bufio"
	"strings"
	"fmt"
	"flag"
	"time"
	"encoding/hex"
	"encoding/binary"
	"os/exec"
	"code.google.com/p/gopacket/pcap"
	"code.google.com/p/gopacket/layers"
	"code.google.com/p/gopacket"
)

func openLiveHandle() (handle *pcap.Handle) {
	var err error
	if handle, err = pcap.OpenLive(gwiface, 1600, true, 0); err != nil {
		panic(err)
	}
	if gfilter != "" {
		log.Println("BPFFilter", gfilter)
		if err = handle.SetBPFFilter(gfilter); err != nil {
			panic(err)
		}
	}
	return
}

func openLiveSource() (src *gopacket.PacketSource, handle *pcap.Handle) {
	handle = openLiveHandle()
	src = gopacket.NewPacketSource(handle, handle.LinkType())
	return
}

func openTestHandle() *pcap.Handle {
	if handle, err := pcap.OpenOffline("test.pcap"); err != nil {
		panic(err)
	} else {
		return handle
	}
}

func liveLoop() {
	if handle := openTestHandle(); handle != nil {
		pktsrc := gopacket.NewPacketSource(handle, handle.LinkType())
		log.Println("starts")
		for pkt := range pktsrc.Packets() {
			log.Println(pkt)
		}
	}
}

func testChangeFields() {
	handle := openTestHandle()
	pktsrc := gopacket.NewPacketSource(handle, handle.LinkType())
	pkt := <-pktsrc.Packets()
	log.Println(pkt)
	tcpLayer := pkt.Layer(layers.LayerTypeTCP)
	tcp, _ := tcpLayer.(*layers.TCP)
	ipLayer := pkt.Layer(layers.LayerTypeIPv4)
	ip, _ := ipLayer.(*layers.IPv4)
	ip.SrcIP = net.IP{1,2,3,4}
	ip.DstIP = net.IP{5,6,7,8}
	tcp.SrcPort = layers.TCPPort(11)
	tcp.DstPort = layers.TCPPort(22)
	ethLayer := pkt.Layer(layers.LayerTypeEthernet)
	eth, _ := ethLayer.(*layers.Ethernet)
	eth.SrcMAC = net.HardwareAddr{1,2,3,4,5,6}
	eth.DstMAC = net.HardwareAddr{6,3,1,2,3,6}

	log.Printf("tcp %v\n", tcp)
	log.Printf("ip %v\n", ip)
	log.Printf("eth %v\n", eth)

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		ComputeChecksums: true,
	}
	tcp.SerializeTo(buf, opts)
	ip.SerializeTo(buf, opts)
	eth.SerializeTo(buf, opts)

	handle2, _ := pcap.OpenLive("lo", 1600, true, 0)
	handle2.WritePacketData(buf.Bytes())

	bytes := buf.Bytes()
	pkt2 := gopacket.NewPacket(bytes, layers.LinkTypeEthernet, gopacket.Default)
	log.Println(pkt2)
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

type Conn struct {
	Packets chan gopacket.Packet
	conn net.Conn
}

func NewConn(conn net.Conn) *Conn {
	t := &Conn{}
	t.Packets = *new(chan gopacket.Packet)
	t.conn = conn
	go t.Run()
	return t
}

func (t *Conn) Write(pkt []byte) (err error) {
	l := uint16(len(pkt))
	binary.Write(t.conn, binary.BigEndian, l)
	_, err = t.conn.Write(pkt)
	return
}

func (t *Conn) Run() {
	var l uint16
	var buf [1600]byte
	for {
		if err := binary.Read(t.conn, binary.BigEndian, &l); err != nil{
			break
		}
		if l > 1600 {
			break
		}
		pbuf := buf[:int(l)]
		if _, err := t.conn.Read(pbuf); err != nil {
			break
		}
		pkt := gopacket.NewPacket(pbuf, layers.LinkTypeEthernet, gopacket.Default)
		t.Packets <- pkt
	}
	t.conn.Close()
	close(t.Packets)
}

type TunnelClient struct {
}

func (t TunnelClient) Run() {
	src, srcw := openLiveSource()

	for {
		host := fmt.Sprintf("%s:%d", ghost, gport)
		log.Println("Connecting", host)
		conn, err := net.DialTimeout("tcp4", host, time.Second*10)
		if err != nil {
			log.Println(err)
			time.Sleep(time.Second)
			continue
		}
		log.Println("Connected", ghost)
		c := NewConn(conn)
		out: for {
			select {
			case in, ok := <-c.Packets:
				srcw.WritePacketData(in.Data())
				if !ok {
					break out
				}
			case out := <-src.Packets():
				c.Write(out.Data())
			}
		}
		log.Println("Closed")
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

func (t *Nat) Parse(pkt gopacket.Packet) (
	eth *layers.Ethernet,
	ip *layers.IPv4,
	tcp *layers.TCP,
	ok bool,
) {
	tcpLayer := pkt.Layer(layers.LayerTypeTCP)
	tcp, _ = tcpLayer.(*layers.TCP)
	ipLayer := pkt.Layer(layers.LayerTypeIPv4)
	ip, _ = ipLayer.(*layers.IPv4)
	ethLayer := pkt.Layer(layers.LayerTypeEthernet)
	eth, _ = ethLayer.(*layers.Ethernet)
	if tcp == nil || ip == nil || eth == nil {
		ok = true
	}
	return
}

func (t *Nat) Hash(ip *layers.IPv4, tcp *layers.TCP) (h uint16) {
	h += 3*uint16(ip.SrcIP[0]) + 23*uint16(ip.SrcIP[1]) +
			 13*uint16(ip.SrcIP[2]) + 31*uint16(ip.SrcIP[3])
	h += 13*uint16(ip.DstIP[0]) + 31*uint16(ip.DstIP[1]) +
			 3*uint16(ip.DstIP[2]) + 23*uint16(ip.DstIP[3])
	h += 37*uint16(tcp.SrcPort)
	return
}

func (t *Nat) Set(pkt gopacket.Packet) (h uint16) {
	return
}

func (t *Nat) In(pkt gopacket.Packet) (b []byte) {
	eth, ip, tcp, ok := t.Parse(pkt)
	if !ok {
		return
	}

	k := tcp.DstPort
	c, _ := t.table[k]
	if c == nil {
		return
	}

	eth.SrcMAC = c.DstMAC
	eth.DstMAC = c.SrcMAC

	ip.DstIP = c.SrcIP
	tcp.DstPort = c.SrcPort

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		ComputeChecksums: true,
	}
	tcp.SerializeTo(buf, opts)
	ip.SerializeTo(buf, opts)
	eth.SerializeTo(buf, opts)

	if tcp.FIN || tcp.RST {
		delete(t.table, k)
	} else {
		c.Ts = time.Now()
	}

	return buf.Bytes()
}

func (t *Nat) Out(pkt gopacket.Packet) (b []byte) {
	eth, ip, tcp, ok := t.Parse(pkt)
	if !ok {
		return
	}

	if tcp.SYN {
		h := t.Set(pkt)
	} else {
	}

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		ComputeChecksums: true,
	}
	tcp.SerializeTo(buf, opts)
	ip.SerializeTo(buf, opts)
	eth.SerializeTo(buf, opts)

	return buf.Bytes()
}

func (t *Nat) Gc() {
}

type TunnelServer struct {
}

func (t TunnelServer) Run() {
	src := openLiveSource()

	ln, err := net.Listen("tcp4", fmt.Sprintf(":%d", gport))
	if err != nil {
		panic(err)
	}
	log.Println("Server starts: listening", gport)

	for {
		conn, err := ln.Accept()
		if err != nil {
			panic(err)
		}
		log.Println("Accepted from", conn.RemoteAddr())

		c := NewConn(conn)
		nat := NewNat()

		out: for {
			select {
			case in, ok := <-c.Packets:
				if !ok {
					break out
				}
				if b := nat.In(in); len(b) > 0 {
					handle.WritePacketData(b)
				}
			case out := <-src.Packets():
				if b := nat.Out(out); len(b) > 0 {
					t.Write(b)
				}
			}
		}
		log.Println("Closed")
	}
}

var (
	gwiface string
	gwip net.IP
	gwmac net.HardwareAddr
	gfilter string //"dst net 95.138.148.0 mask 255.255.255.0"
	gport int
	ghost string
)

func main() {
	// "106.187.99.23:1988"
	log.Println("starts")

	flag.StringVar(&ghost, "h", "", "tunnel server host ip")
	flag.IntVar(&gport, "p", 9998, "tunnel server listen port")
	flag.StringVar(&gfilter, "f", "", "tunnel pcap filter")
	flag.Parse()

	gwiface, gwip, gwmac = findGateway()
	log.Println("Found gateway", gwiface, gwip, gwmac)

	if ghost != "" {
		srv := TunnelServer{}
		srv.Run()
	} else {
		cli := TunnelClient{}
		cli.Run()
	}
}

