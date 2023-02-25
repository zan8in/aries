package aries

import (
	"fmt"
	"math/rand"
	"net"
	"os"
	"time"

	"github.com/remeh/sizedwaitgroup"
	"github.com/zan8in/aries/pkg/util/mapcidr"
	"github.com/zan8in/gologger"
)

type Runner struct {
	options      *Options
	scanner      *Scanner
	tempHostFile string // os.CreateTemp() file name
	hostChan     chan *net.IPNet
	ticker       *time.Ticker
	wgscan       sizedwaitgroup.SizedWaitGroup
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

	return runner, err
}

func (runner *Runner) Run() error {
	var err error
	defer runner.Close()

	if runner.options.isSynScan() {
		fmt.Println("SYN")
	}

	go runner.PreprocessingHosts()

	runner.start()

	return err
}

func (runner *Runner) start() {
	rand.Seed(time.Now().UnixNano())

	runner.wgscan = sizedwaitgroup.New(runner.options.RateLimit)
	runner.ticker = time.NewTicker(time.Second / time.Duration(runner.options.RateLimit))

	isSynScanType := runner.options.isSynScan()
	fmt.Println("is SYN? ", isSynScanType)

	for cidr := range runner.hostChan {
		ipStream, _ := mapcidr.IPAddressesAsStream(cidr.String())
		for ip := range ipStream {
			for _, port := range runner.scanner.Ports {
				if runner.scanner.ScanResults.HasSkipped(ip) {
					continue
				}
				if isSynScanType {

				} else {
					runner.wgscan.Add()
					go runner.connectScan(ip, port)
				}
			}

		}
	}
	runner.wgscan.Wait()
}

func (runner *Runner) Listener() {
	fmt.Println("Listen end")
	runner.output(runner.scanner.ScanResults)
}

func (runner *Runner) connectScan(host string, port int) {
	defer runner.wgscan.Done()

	if runner.scanner.ScanResults.IPHasPort(host, port) {
		return
	}

	<-runner.ticker.C

	open, err := runner.scanner.ConnectPort(host, port, time.Duration(runner.options.Timeout)*time.Millisecond)
	if open && err == nil {
		gologger.Print().Msgf("%s:%d", host, port)
		runner.scanner.ScanResults.AddPort(host, port)
	}
}

// Close runner instance
func (runner *Runner) Close() {
	os.RemoveAll(runner.tempHostFile)
}
