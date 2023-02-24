package aries

import (
	"net"

	"github.com/zan8in/aries/pkg/util/mapcidr"
	"github.com/zan8in/gologger"
)

type Runner struct {
	options      *Options
	scanner      *Scanner
	TempHostFile string // os.CreateTemp() file name
	hostChan     chan *net.IPNet
}

func NewRunner(options *Options) (*Runner, error) {
	runner := &Runner{
		options: options,
	}
	runner.hostChan = make(chan *net.IPNet)

	scanner, err := NewScanner(options)
	if err != nil {
		return runner, err
	}
	runner.scanner = scanner

	runner.scanner.Ports, err = ParsePorts(options)
	if err != nil {
		return runner, err
	}

	go runner.ScanHost()

	err = runner.ParseHosts()
	if err != nil {
		return runner, err
	}

	return runner, err
}

func (runner *Runner) ScanHost() {
	for cidr := range runner.hostChan {
		ipStream, _ := mapcidr.IPAddressesAsStream(cidr.String())
		for ip := range ipStream {
			gologger.Print().Msg(ip)
		}
	}
}
