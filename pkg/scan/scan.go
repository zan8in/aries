package scan

import (
	"errors"
	"fmt"
	"math/rand"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/zan8in/aries/pkg/freeport"
	"github.com/zan8in/aries/pkg/ipranger"
	"github.com/zan8in/aries/pkg/port"
	"github.com/zan8in/aries/pkg/privileges"
	"github.com/zan8in/aries/pkg/protocol"
	"github.com/zan8in/aries/pkg/result"
	"github.com/zan8in/aries/pkg/routing"
	"github.com/zan8in/aries/pkg/util/iputil"
	"github.com/zan8in/gologger"
	"golang.org/x/net/proxy"
)

// Some constants
const (
	ProtocolICMP     = 1
	ProtocolIPv6ICMP = 58
)

// State determines the internal scan state
type State int

const (
	maxRetries     = 10
	sendDelayMsec  = 10
	chanSize       = 1000  //nolint
	packetSendSize = 2500  //nolint
	snaplen        = 65536 //nolint
	readtimeout    = 1500  //nolint
)

const (
	Init State = iota
	Scan
	Done
	Guard
)

type Phase struct {
	sync.RWMutex
	State
}

func (phase *Phase) Is(state State) bool {
	phase.RLock()
	defer phase.RUnlock()

	return phase.State == state
}

func (phase *Phase) Set(state State) {
	phase.Lock()
	defer phase.Unlock()

	phase.State = state
}

// PkgFlag represent the TCP packet flag
type PkgFlag int

const (
	Syn PkgFlag = iota
	Ack
)

// Options of the scan
type OptionsScanner struct {
	Timeout     time.Duration
	Retries     int
	Rate        int
	Debug       bool
	ExcludedIps []string
	Proxy       string
	ProxyAuth   string
	Stream      bool
}

type Scanner struct {
	Router             routing.Router
	SourceIP4          net.IP
	SourceIP6          net.IP
	tcpPacketListener4 net.PacketConn
	udpPacketListener4 net.PacketConn
	tcpPacketListener6 net.PacketConn
	udpPacketListener6 net.PacketConn
	retries            int
	rate               int
	SourcePort         int
	timeout            time.Duration
	proxyDialer        proxy.Dialer

	Ports    []*port.Port
	IPRanger *ipranger.IPRanger

	transportPacketSend chan *PkgSend
	tcpChan             chan *PkgResult
	udpChan             chan *PkgResult
	Phase               Phase
	ScanResults         *result.Result
	NetworkInterface    *net.Interface
	tcpsequencer        *TCPSequencer
	serializeOptions    gopacket.SerializeOptions
	debug               bool
	handlers            interface{} //nolint
	stream              bool
}

// PkgSend is a TCP package
type PkgSend struct {
	ip       string
	port     *port.Port
	flag     PkgFlag
	SourceIP string
}

// PkgResult contains the results of sending TCP packages
type PkgResult struct {
	ip   string
	port *port.Port
}

var (
	newScannerCallback        func(s *Scanner) error
	setupHandlerCallback      func(s *Scanner, interfaceName, bpfFilter string, protocols ...protocol.Protocol) error
	tcpReadWorkerPCAPCallback func(s *Scanner)
	cleanupHandlersCallback   func(s *Scanner)
)

// NewScanner creates a new full port scanner that scans all ports using SYN packets.
func NewScanner(options *OptionsScanner) (*Scanner, error) {
	rand.Seed(time.Now().UnixNano())

	iprang, err := ipranger.New()
	if err != nil {
		return nil, err
	}

	scanner := &Scanner{
		serializeOptions: gopacket.SerializeOptions{
			FixLengths:       true,
			ComputeChecksums: true,
		},
		timeout:      options.Timeout,
		retries:      options.Retries,
		rate:         options.Rate,
		debug:        options.Debug,
		tcpsequencer: NewTCPSequencer(),
		IPRanger:     iprang,
	}

	if privileges.IsPrivileged && newScannerCallback != nil {
		if err := newScannerCallback(scanner); err != nil {
			return nil, err
		}
	}

	scanner.ScanResults = result.NewResult()

	scanner.stream = options.Stream

	return scanner, nil
}

// Close the scanner and terminate all workers
func (s *Scanner) Close() {
	s.CleanupHandlers()
	s.tcpPacketListener4.Close()
	s.tcpPacketListener6.Close()
}

// StartWorkers of the scanner
func (s *Scanner) StartWorkers() {
	go s.TCPReadWorker4()
	go s.TCPReadWorker6()
	go s.TCPReadWorkerPCAP()
	go s.TransportWriteWorker()
	go s.TCPResultWorker()
}

// TCPWriteWorker that sends out TCP|UDP packets
func (s *Scanner) TransportWriteWorker() {
	for pkg := range s.transportPacketSend {
		s.SendAsyncPkg(pkg.ip, pkg.port, pkg.flag)
	}
}

// TCPReadWorker4 reads and parse incoming TCP packets
func (s *Scanner) TCPReadWorker4() {
	defer s.tcpPacketListener4.Close()
	data := make([]byte, 4096)
	for {
		if s.Phase.Is(Done) {
			break
		}
		// nolint:errcheck // just empty the buffer
		s.tcpPacketListener4.ReadFrom(data)
	}
}

// TCPReadWorker4 reads and parse incoming TCP packets
func (s *Scanner) TCPReadWorker6() {
	defer s.tcpPacketListener6.Close()
	data := make([]byte, 4096)
	for {
		if s.Phase.Is(Done) {
			break
		}
		// nolint:errcheck // just empty the buffer
		s.tcpPacketListener6.ReadFrom(data)
	}
}

// TCPReadWorkerPCAP reads and parse incoming TCP packets with pcap
func (s *Scanner) TCPReadWorkerPCAP() {
	if tcpReadWorkerPCAPCallback != nil {
		tcpReadWorkerPCAPCallback(s)
	}
}

// EnqueueTCP outgoing TCP packets
func (s *Scanner) EnqueueTCP(ip string, pkgtype PkgFlag, ports ...*port.Port) {
	for _, port := range ports {
		s.transportPacketSend <- &PkgSend{
			ip:   ip,
			port: port,
			flag: pkgtype,
		}
	}
}

// TCPResultWorker handles probes and scan results
func (s *Scanner) TCPResultWorker() {
	for ip := range s.tcpChan {
		if s.Phase.Is(Scan) || s.stream {
			if s.debug {
				gologger.Debug().Msgf("Received Transport (TCP) scan response from %s:%d\n", ip.ip, ip.port.Port)
			}
			s.ScanResults.AddPort(ip.ip, ip.port)
		}
	}
}

// send sends the given layers as a single packet on the network.
func (s *Scanner) send(destIP string, conn net.PacketConn, l ...gopacket.SerializableLayer) error {
	buf := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buf, s.serializeOptions, l...); err != nil {
		return err
	}

	var (
		retries int
		err     error
	)

send:
	if retries >= maxRetries {
		return err
	}
	_, err = conn.WriteTo(buf.Bytes(), &net.IPAddr{IP: net.ParseIP(destIP)})
	if err != nil {
		retries++
		// introduce a small delay to allow the network interface to flush the queue
		time.Sleep(time.Duration(sendDelayMsec) * time.Millisecond)
		goto send
	}
	return err
}

// ScanSyn a target ip
func (s *Scanner) ScanSyn(ip string) {
	for _, port := range s.Ports {
		s.EnqueueTCP(ip, Syn, port)
	}
}

// GetInterfaceFromIP gets the name of the network interface from local ip address
func GetInterfaceFromIP(ip net.IP) (*net.Interface, error) {
	address := ip.String()

	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	for _, i := range interfaces {
		byNameInterface, err := net.InterfaceByName(i.Name)
		if err != nil {
			return nil, err
		}

		addresses, err := byNameInterface.Addrs()
		if err != nil {
			return nil, err
		}

		for _, v := range addresses {
			// Check if the IP for the current interface is our
			// source IP. If yes, return the interface
			if strings.HasPrefix(v.String(), address+"/") {
				return byNameInterface, nil
			}
		}
	}

	return nil, fmt.Errorf("no interface found for ip %s", address)
}

// ACKPort sends an ACK packet to a port
func (s *Scanner) ACKPort(dstIP string, port int, timeout time.Duration) (bool, error) {
	conn, err := net.ListenPacket("ip4:tcp", "0.0.0.0")
	if err != nil {
		return false, err
	}
	defer conn.Close()

	rawPort, err := freeport.GetFreeTCPPort("")
	if err != nil {
		return false, err
	}

	// Construct all the network layers we need.
	ip4 := layers.IPv4{
		DstIP:    net.ParseIP(dstIP),
		Version:  4,
		TTL:      255,
		Protocol: layers.IPProtocolTCP,
	}

	if s.SourceIP4 != nil {
		ip4.SrcIP = s.SourceIP4
	} else if s.Router != nil {
		_, _, sourceIP, err := s.Router.Route(ip4.DstIP)
		if err != nil {
			return false, err
		}
		ip4.SrcIP = sourceIP
	} else {
		return false, errors.New("could not find routes")
	}

	tcpOption := layers.TCPOption{
		OptionType:   layers.TCPOptionKindMSS,
		OptionLength: 4,
		OptionData:   []byte{0x12, 0x34},
	}

	tcp := layers.TCP{
		SrcPort: layers.TCPPort(rawPort.Port),
		DstPort: layers.TCPPort(port),
		ACK:     true,
		Window:  1024,
		Seq:     s.tcpsequencer.Next(),
		Options: []layers.TCPOption{tcpOption},
	}

	err = tcp.SetNetworkLayerForChecksum(&ip4)
	if err != nil {
		return false, err
	}

	err = s.send(dstIP, conn, &tcp)
	if err != nil {
		return false, err
	}

	data := make([]byte, 4096)
	for {
		n, addr, err := conn.ReadFrom(data)
		if err != nil {
			break
		}

		// not matching ip
		if addr.String() != dstIP {
			if s.debug {
				gologger.Debug().Msgf("Discarding TCP packet from non target ip %s for %s\n", dstIP, addr.String())
			}
			continue
		}

		packet := gopacket.NewPacket(data[:n], layers.LayerTypeTCP, gopacket.Default)
		if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
			tcp, ok := tcpLayer.(*layers.TCP)
			if !ok {
				continue
			}
			// We consider only incoming packets
			if tcp.DstPort != layers.TCPPort(rawPort.Port) {
				if s.debug {
					gologger.Debug().Msgf("Discarding TCP packet from %s:%d not matching %s:%d port\n", addr.String(), tcp.DstPort, dstIP, rawPort.Port)
				}
				continue
			} else if tcp.RST {
				if s.debug {
					gologger.Debug().Msgf("Accepting RST packet from %s:%d\n", addr.String(), tcp.DstPort)
					return true, nil
				}
			}
		}
	}

	return false, nil
}

// SendAsyncPkg sends a single packet to a port
func (s *Scanner) SendAsyncPkg(ip string, p *port.Port, pkgFlag PkgFlag) {
	isIP4 := iputil.IsIPv4(ip)
	isIP6 := iputil.IsIPv6(ip)
	isTCP := p.Protocol == protocol.TCP
	switch {
	case isIP4 && isTCP:
		s.sendAsyncTCP4(ip, p, pkgFlag)
	case isIP6 && isTCP:
		s.sendAsyncTCP6(ip, p, pkgFlag)
	}
}

func (s *Scanner) sendAsyncTCP4(ip string, p *port.Port, pkgFlag PkgFlag) {
	// Construct all the network layers we need.
	ip4 := layers.IPv4{
		DstIP:    net.ParseIP(ip),
		Version:  4,
		TTL:      255,
		Protocol: layers.IPProtocolTCP,
	}
	if s.SourceIP4 != nil {
		ip4.SrcIP = s.SourceIP4
	} else {
		_, _, sourceIP, err := s.Router.Route(ip4.DstIP)
		if err != nil {
			gologger.Debug().Msgf("could not find route to host %s:%d: %s\n", ip, p.Port, err)
			return
		} else if sourceIP == nil {
			gologger.Debug().Msgf("could not find correct source ipv4 for %s:%d\n", ip, p.Port)
			return
		}
		ip4.SrcIP = sourceIP
	}

	tcpOption := layers.TCPOption{
		OptionType:   layers.TCPOptionKindMSS,
		OptionLength: 4,
		OptionData:   []byte{0x05, 0xB4},
	}

	tcp := layers.TCP{
		SrcPort: layers.TCPPort(s.SourcePort),
		DstPort: layers.TCPPort(p.Port),
		Window:  1024,
		Seq:     s.tcpsequencer.Next(),
		Options: []layers.TCPOption{tcpOption},
	}

	if pkgFlag == Syn {
		tcp.SYN = true
	} else if pkgFlag == Ack {
		tcp.ACK = true
	}

	err := tcp.SetNetworkLayerForChecksum(&ip4)
	if err != nil {
		if s.debug {
			gologger.Debug().Msgf("Can not set network layer for %s:%d port: %s\n", ip, p.Port, err)
		}
	} else {
		err = s.send(ip, s.tcpPacketListener4, &tcp)
		if err != nil {
			if s.debug {
				gologger.Debug().Msgf("Can not send packet to %s:%d port: %s\n", ip, p.Port, err)
			}
		}
	}
}

func (s *Scanner) sendAsyncTCP6(ip string, p *port.Port, pkgFlag PkgFlag) {
	// Construct all the network layers we need.
	ip6 := layers.IPv6{
		DstIP:      net.ParseIP(ip),
		Version:    6,
		HopLimit:   255,
		NextHeader: layers.IPProtocolTCP,
	}

	if s.SourceIP6 != nil {
		ip6.SrcIP = s.SourceIP6
	} else {
		_, _, sourceIP, err := s.Router.Route(ip6.DstIP)
		if err != nil {
			gologger.Debug().Msgf("could not find route to host %s:%d: %s\n", ip, p.Port, err)
			return
		} else if sourceIP == nil {
			gologger.Debug().Msgf("could not find correct source ipv6 for %s:%d\n", ip, p.Port)
			return
		}
		ip6.SrcIP = sourceIP
	}

	tcpOption := layers.TCPOption{
		OptionType:   layers.TCPOptionKindMSS,
		OptionLength: 4,
		OptionData:   []byte{0x05, 0xB4},
	}

	tcp := layers.TCP{
		SrcPort: layers.TCPPort(s.SourcePort),
		DstPort: layers.TCPPort(p.Port),
		Window:  1024,
		Seq:     s.tcpsequencer.Next(),
		Options: []layers.TCPOption{tcpOption},
	}

	if pkgFlag == Syn {
		tcp.SYN = true
	} else if pkgFlag == Ack {
		tcp.ACK = true
	}

	err := tcp.SetNetworkLayerForChecksum(&ip6)
	if err != nil {
		if s.debug {
			gologger.Debug().Msgf("Can not set network layer for %s:%d port: %s\n", ip, p.Port, err)
		}
	} else {
		err = s.send(ip, s.tcpPacketListener6, &tcp)
		if err != nil {
			if s.debug {
				gologger.Debug().Msgf("Can not send packet to %s:%d port: %s\n", ip, p.Port, err)
			}
		}
	}
}

// SetupHandlers to listen on all interfaces
func (s *Scanner) SetupHandlers() error {
	if s.NetworkInterface != nil {
		return s.SetupHandler(s.NetworkInterface.Name)
	}

	// listen on all interfaces manually
	// unfortunately s.SetupHandler("any") causes ip4 to be ignored
	itfs, err := net.Interfaces()
	if err != nil {
		return err
	}
	for _, itf := range itfs {
		isInterfaceDown := itf.Flags&net.FlagUp == 0
		if isInterfaceDown {
			continue
		}
		if err := s.SetupHandler(itf.Name); err != nil {
			gologger.Warning().Msgf("Error on interface %s: %s", itf.Name, err)
		}
	}

	return nil
}

// SetupHandler to listen on the specified interface
func (s *Scanner) SetupHandler(interfaceName string) error {
	bpfFilter := fmt.Sprintf("dst port %d and (tcp or udp)", s.SourcePort)
	if setupHandlerCallback != nil {
		err := setupHandlerCallback(s, interfaceName, bpfFilter, protocol.TCP)
		if err != nil {
			return err
		}
	}
	// arp filter should be improved with source mac
	// https://stackoverflow.com/questions/40196549/bpf-expression-to-capture-only-arp-reply-packets
	// (arp[6:2] = 2) and dst host host and ether dst mac
	bpfFilter = "arp"
	if setupHandlerCallback != nil {
		err := setupHandlerCallback(s, interfaceName, bpfFilter, protocol.ARP)
		if err != nil {
			return err
		}
	}

	return nil
}

// CleanupHandlers for all interfaces
func (s *Scanner) CleanupHandlers() {
	if cleanupHandlersCallback != nil {
		cleanupHandlersCallback(s)
	}
}
