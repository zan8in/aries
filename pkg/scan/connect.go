package scan

import (
	"fmt"
	"io"
	"net"
	"os"
	"time"

	"github.com/zan8in/aries/pkg/port"
	"github.com/zan8in/aries/pkg/probeservice/vscan"
	"github.com/zan8in/aries/pkg/protocol"
)

const (
	DeadlineSec = 10
)

func (s *Scanner) ConnectPort(host string, p *port.Port, timeout time.Duration) (bool, error) {
	hostport := net.JoinHostPort(host, fmt.Sprint(p.Port))
	var (
		err  error
		conn net.Conn
	)

	retries := 0
send:
	if retries >= s.retries {
		return false, err
	}

	conn, err = net.DialTimeout(p.Protocol.String(), hostport, timeout)
	if err != nil {
		retries++
		time.Sleep(time.Duration(DeadlineSec) * time.Millisecond)
		goto send
	}
	defer conn.Close()

	switch p.Protocol {
	case protocol.UDP:
		if err := conn.SetWriteDeadline(time.Now().Add(timeout)); err != nil {
			retries++
			time.Sleep(time.Duration(DeadlineSec) * time.Millisecond)
			goto send
		}
		if _, err := conn.Write(nil); err != nil {
			retries++
			time.Sleep(time.Duration(DeadlineSec) * time.Millisecond)
			goto send
		}
		if err := conn.SetReadDeadline(time.Now().Add(timeout)); err != nil {
			retries++
			time.Sleep(time.Duration(DeadlineSec) * time.Millisecond)
			goto send
		}
		n, _ := io.Copy(io.Discard, conn)
		// ignore timeout errors
		if err != nil && !os.IsTimeout(err) {
			retries++
			time.Sleep(time.Duration(DeadlineSec) * time.Millisecond)
			goto send
		}
		return n > 0, nil
	}

	return true, err
}

func (s *Scanner) NmapServiceProbesScan(host string, ports []*port.Port) []*port.Port {
	var verifiedPorts []*port.Port

	for _, p := range ports {

		service, probeProduct, version := vscan.Vs.Check("tcp", host, p.Port)
		pp := &port.Port{
			Port:         p.Port,
			Protocol:     p.Protocol,
			TLS:          p.TLS,
			Service:      service,
			ProbeProduct: probeProduct,
			Version:      version,
		}

		verifiedPorts = append(verifiedPorts, pp)
	}

	return verifiedPorts
}

func ServiceScan(ip string, port int) (string, string, string) {
	return vscan.Vs.Check("tcp", ip, port)
}
