package scan

import (
	"fmt"
	"io"
	"net"
	"os"
	"time"

	"github.com/zan8in/aries/pkg/port"
	"github.com/zan8in/aries/pkg/protocol"
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
