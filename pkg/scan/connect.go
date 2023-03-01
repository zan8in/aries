package scan

import (
	"fmt"
	"io"
	"net"
	"os"
	"time"

	"github.com/zan8in/aries/pkg/port"
	"github.com/zan8in/aries/pkg/probeservice"
	"github.com/zan8in/aries/pkg/protocol"
	"github.com/zan8in/gologger"
)

const (
	DeadlineSec = 10
)

// ConnectPort a single host and port
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

	// udp needs data probe
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

func (s *Scanner) ConnectVerify(host string, ports []*port.Port) []*port.Port {
	var verifiedPorts []*port.Port

	defer func() {
		if r := recover(); r != nil {
			gologger.Debug().Msg(r.(string))
		}
	}()

	for _, p := range ports {

		conn, err := net.DialTimeout(p.Protocol.String(), fmt.Sprintf("%s:%d", host, p.Port), s.timeout)
		if err != nil {
			verifiedPorts = append(verifiedPorts, p)
			continue
		}
		defer conn.Close()

		buf := make([]byte, 0, 1024)
		tmp := make([]byte, 512)
		for {
			if err = conn.SetReadDeadline(time.Now().Add(s.timeout)); err != nil {
				break
			}
			n, err := conn.Read(tmp)
			if err != nil {
				break
			}
			buf = append(buf, tmp[:n]...)
		}
		// fmt.Println(string(buf))
		service, probeProduct, title, httpFlag := probeservice.Start(string(buf), host, p.Port)
		pp := &port.Port{
			Port:         p.Port,
			Protocol:     p.Protocol,
			TLS:          p.TLS,
			Service:      service,
			ProbeProduct: probeProduct,
			Title:        title,
			Http:         httpFlag,
		}

		verifiedPorts = append(verifiedPorts, pp)
	}

	return verifiedPorts
}
