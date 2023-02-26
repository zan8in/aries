package aries

import (
	"fmt"
	"math/rand"
	"net"
	"os"
	"time"

	"github.com/remeh/sizedwaitgroup"
	"github.com/zan8in/aries/pkg/port"
	"github.com/zan8in/aries/pkg/privileges"
	"github.com/zan8in/aries/pkg/scan"
	"github.com/zan8in/aries/pkg/util/dateutil"
	"github.com/zan8in/aries/pkg/util/mapcidr"
	"github.com/zan8in/gologger"
)

type Runner struct {
	options *Options
	scanner *scan.Scanner

	ticker *time.Ticker
	wgscan sizedwaitgroup.SizedWaitGroup

	hostChan chan *net.IPNet

	tempHostFile string
}

func NewRunner(options *Options) (*Runner, error) {
	runner := &Runner{
		options: options,
	}
	runner.hostChan = make(chan *net.IPNet)

	scanner, err := scan.NewScanner(&scan.OptionsScanner{
		Timeout: time.Duration(options.Timeout) * time.Millisecond,
		Retries: options.Retries,
		Rate:    options.RateLimit,
		Debug:   options.Debug,
		Stream:  true,
	})
	if err != nil {
		return runner, err
	}
	runner.scanner = scanner

	runner.scanner.Ports, err = ParsePorts(options)
	if err != nil {
		return runner, err
	}

	runner.wgscan = sizedwaitgroup.New(runner.options.RateLimit)
	runner.ticker = time.NewTicker(time.Second / time.Duration(runner.options.RateLimit))

	return runner, err
}

func (runner *Runner) Run() error {
	defer runner.Close()

	if privileges.IsPrivileged && runner.options.ScanType == SynScan {
		err := runner.scanner.SetupHandlers()
		if err != nil {
			return err
		}
		runner.BackgroundWorkers()
	}

	go runner.PreprocessingHosts()

	runner.start()

	return nil
}

func (r *Runner) BackgroundWorkers() {
	r.scanner.StartWorkers()
}

func (runner *Runner) start() {
	rand.Seed(time.Now().UnixNano())

	isSynScanType := runner.options.isSynScan()
	gologger.Print().Msgf("Running [%s] scan. Start time %s\n", runner.options.scanType(), dateutil.GetNowFullDateTime())

	for cidr := range runner.hostChan {
		ipStream, _ := mapcidr.IPAddressesAsStream(cidr.String())
		for ip := range ipStream {
			for _, port := range runner.scanner.Ports {
				if runner.scanner.ScanResults.HasSkipped(ip) {
					continue
				}
				if isSynScanType {
					runner.scanner.Phase.Set(scan.Scan)
					runner.handleHostPortSyn(ip, port)
				} else {
					runner.wgscan.Add()
					go runner.connectScan(ip, port)
				}
			}

		}
	}
	runner.wgscan.Wait()

	runner.scanner.Phase.Set(scan.Done)

	runner.handleOutput(runner.scanner.ScanResults)

	gologger.Print().Msgf("\nAries finished at %s\n", dateutil.GetNowFullDateTime())
}

func (runner *Runner) Listener() {
	fmt.Println("Listen end")
	runner.handleOutput(runner.scanner.ScanResults)
}

func (r *Runner) handleHostPortSyn(ip string, p *port.Port) {
	<-r.ticker.C
	r.scanner.EnqueueTCP(ip, scan.Syn, p)
}

func (runner *Runner) connectScan(host string, port *port.Port) {
	defer runner.wgscan.Done()

	if runner.scanner.ScanResults.IPHasPort(host, port) {
		return
	}

	<-runner.ticker.C

	open, err := runner.scanner.ConnectPort(host, port, time.Duration(runner.options.Timeout)*time.Millisecond)
	if open && err == nil {
		if runner.options.Debug {
			gologger.Print().Msgf("Received Transport (TCP) scan response from %s:%d\n", host, port.Port)
		}
		runner.scanner.ScanResults.AddPort(host, port)
	}
}

// Close runner instance
func (runner *Runner) Close() {
	os.RemoveAll(runner.tempHostFile)
}
