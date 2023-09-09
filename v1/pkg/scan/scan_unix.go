//go:build linux || darwin

package scan

import (
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/zan8in/aries/pkg/freeport"
	"github.com/zan8in/aries/pkg/port"
	"github.com/zan8in/aries/pkg/protocol"
	"github.com/zan8in/aries/pkg/routing"
	"github.com/zan8in/gologger"
)

func init() {
	newScannerCallback = NewScannerUnix
	setupHandlerCallback = SetupHandlerUnix
	tcpReadWorkerPCAPCallback = TransportReadWorkerPCAPUnix
	cleanupHandlersCallback = CleanupHandlersUnix
}

// Handlers contains the list of pcap handlers
type Handlers struct {
	TransportActive   []*pcap.Handle
	TransportInactive []*pcap.InactiveHandle
	EthernetActive    []*pcap.Handle
	EthernetInactive  []*pcap.InactiveHandle
}

func getFreePort() (int, error) {
	rawPort, err := freeport.GetFreeTCPPort("")
	if err != nil {
		return 0, err
	}
	return rawPort.Port, nil
}

// NewScannerUnix creates a new instance specific for unix OS
func NewScannerUnix(scanner *Scanner) error {
	if scanner.SourcePort <= 0 {
		rawport, err := getFreePort()
		if err != nil {
			return err
		}
		scanner.SourcePort = rawport
	}

	tcpConn4, err := net.ListenIP("ip4:tcp", &net.IPAddr{IP: net.ParseIP(fmt.Sprintf("0.0.0.0:%d", scanner.SourcePort))})
	if err != nil {
		return err
	}
	scanner.tcpPacketListener4 = tcpConn4

	udpConn4, err := net.ListenIP("ip4:udp", &net.IPAddr{IP: net.ParseIP(fmt.Sprintf("0.0.0.0:%d", scanner.SourcePort))})
	if err != nil {
		return err
	}
	scanner.udpPacketListener4 = udpConn4

	tcpConn6, err := net.ListenIP("ip6:tcp", &net.IPAddr{IP: net.ParseIP(fmt.Sprintf(":::%d", scanner.SourcePort))})
	if err != nil {
		return err
	}
	scanner.tcpPacketListener6 = tcpConn6

	udpConn6, err := net.ListenIP("ip6:udp", &net.IPAddr{IP: net.ParseIP(fmt.Sprintf(":::%d", scanner.SourcePort))})
	if err != nil {
		return err
	}
	scanner.udpPacketListener6 = udpConn6

	var handlers Handlers
	scanner.handlers = handlers

	scanner.tcpChan = make(chan *PkgResult, chanSize)
	scanner.udpChan = make(chan *PkgResult, chanSize)
	scanner.transportPacketSend = make(chan *PkgSend, packetSendSize)

	scanner.Router, err = routing.New()

	return err
}

// SetupHandlerUnix on unix OS
func SetupHandlerUnix(s *Scanner, interfaceName, bpfFilter string, protocols ...protocol.Protocol) error {
	for _, proto := range protocols {
		inactive, err := pcap.NewInactiveHandle(interfaceName)
		if err != nil {
			return err
		}

		err = inactive.SetSnapLen(snaplen)
		if err != nil {
			return err
		}

		readTimeout := time.Duration(readtimeout) * time.Millisecond
		if err = inactive.SetTimeout(readTimeout); err != nil {
			s.CleanupHandlers()
			return err
		}
		err = inactive.SetImmediateMode(true)
		if err != nil {
			return err
		}

		handlers, ok := s.handlers.(Handlers)
		if !ok {
			return errors.New("couldn't create handlers")
		}

		switch proto {
		case protocol.TCP, protocol.UDP:
			handlers.TransportInactive = append(handlers.TransportInactive, inactive)
		case protocol.ARP:
			handlers.EthernetInactive = append(handlers.EthernetInactive, inactive)
		default:
			panic("protocol not supported")
		}

		handle, err := inactive.Activate()
		if err != nil {
			s.CleanupHandlers()
			return err
		}

		// Strict BPF filter
		// + Destination port equals to sender socket source port
		err = handle.SetBPFFilter(bpfFilter)
		if err != nil {
			return err
		}

		switch proto {
		case protocol.TCP, protocol.UDP:
			handlers.TransportActive = append(handlers.TransportActive, handle)
		case protocol.ARP:
			handlers.EthernetActive = append(handlers.EthernetActive, handle)
		default:
			panic("protocol not supported")
		}
		s.handlers = handlers
	}

	return nil
}

// TransportReadWorkerPCAPUnix for TCP and UDP
func TransportReadWorkerPCAPUnix(s *Scanner) {
	defer s.CleanupHandlers()

	var wgread sync.WaitGroup

	handlers, ok := s.handlers.(Handlers)
	if !ok {
		return
	}

	// Transport Readers (TCP|UDP)
	for _, handler := range handlers.TransportActive {

		wgread.Add(1)
		go func(handler *pcap.Handle) {
			defer wgread.Done()

			var (
				eth layers.Ethernet
				ip4 layers.IPv4
				ip6 layers.IPv6
				tcp layers.TCP
				udp layers.UDP
			)

			// Interfaces with MAC (Physical + Virtualized)
			parser4Mac := gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet, &eth, &ip4, &tcp, &udp)
			parser6Mac := gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet, &eth, &ip6, &tcp, &udp)
			// Interfaces without MAC (TUN/TAP)
			parser4NoMac := gopacket.NewDecodingLayerParser(layers.LayerTypeIPv4, &ip4, &tcp, &udp)
			parser6NoMac := gopacket.NewDecodingLayerParser(layers.LayerTypeIPv6, &ip6, &tcp, &udp)

			var parsers []*gopacket.DecodingLayerParser
			parsers = append(parsers,
				parser4Mac, parser6Mac,
				parser4NoMac, parser6NoMac,
			)

			decoded := []gopacket.LayerType{}

			for {
				data, _, err := handler.ReadPacketData()
				if err == io.EOF {
					break
				} else if err != nil {
					continue
				}

				for _, parser := range parsers {
					err := parser.DecodeLayers(data, &decoded)
					if err != nil {
						continue
					}
					for _, layerType := range decoded {
						if layerType == layers.LayerTypeTCP || layerType == layers.LayerTypeUDP {
							srcIP4 := ip4.SrcIP.String()
							isIP4InRange := s.IPRanger.Contains(srcIP4)
							srcIP6 := ip6.SrcIP.String()
							isIP6InRange := s.IPRanger.Contains(srcIP6)
							var ip string
							if isIP4InRange {
								ip = srcIP4
							} else if isIP6InRange {
								ip = srcIP6
							} else {
								gologger.Debug().Msgf("Discarding Transport packet from non target ips: ip4=%s ip6=%s\n", srcIP4, srcIP6)
								continue
							}

							// We consider only incoming packets
							tcpPortMatches := tcp.DstPort == layers.TCPPort(s.SourcePort)
							udpPortMatches := udp.DstPort == layers.UDPPort(s.SourcePort)
							sourcePortMatches := tcpPortMatches || udpPortMatches
							switch {
							case !sourcePortMatches:
								gologger.Debug().Msgf("Discarding Transport packet from non target ips: ip4=%s ip6=%s tcp_dport=%d udp_dport=%d\n", srcIP4, srcIP6, tcp.DstPort, udp.DstPort)
								continue
							case tcpPortMatches && tcp.SYN && tcp.ACK:
								s.tcpChan <- &PkgResult{ip: ip, port: &port.Port{Port: int(tcp.SrcPort), Protocol: protocol.TCP}}
							case udpPortMatches && udp.Length > 0: // needs a better matching of udp payloads
								s.udpChan <- &PkgResult{ip: ip, port: &port.Port{Port: int(udp.SrcPort), Protocol: protocol.UDP}}
							}
						}
					}
				}
			}
		}(handler)
	}

	wgread.Wait()
}

// CleanupHandlers for all interfaces
func CleanupHandlersUnix(s *Scanner) {
	if handlers, ok := s.handlers.(Handlers); ok {
		for _, handler := range append(handlers.TransportActive, handlers.EthernetActive...) {
			handler.Close()
		}
		for _, inactiveHandler := range append(handlers.TransportInactive, handlers.EthernetInactive...) {
			inactiveHandler.CleanUp()
		}
	}
}
