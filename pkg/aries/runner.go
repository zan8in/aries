package aries

import (
	"bufio"
	"fmt"
	"math/rand"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/remeh/sizedwaitgroup"
	"github.com/zan8in/aries/pkg/port"
	"github.com/zan8in/aries/pkg/privileges"
	"github.com/zan8in/aries/pkg/result"
	"github.com/zan8in/aries/pkg/scan"
	"github.com/zan8in/aries/pkg/util/dateutil"
	"github.com/zan8in/aries/pkg/util/mapcidr"
	"github.com/zan8in/aries/pkg/util/sliceutil"
	"github.com/zan8in/gologger"
	iptuil "github.com/zan8in/pins/ip"
)

type OnResultCallback func(r Result)

type Runner struct {
	options *Options
	Scanner *scan.Scanner

	ticker *time.Ticker
	wgscan sizedwaitgroup.SizedWaitGroup

	hostChan          chan *net.IPNet
	hostDiscoveryChan chan *net.IPNet
	hostStrChan       chan string

	tempHostFile string

	HostCount int32
	PortCount int32

	OnResult OnResultCallback
}

type Result struct {
	Host     string
	IP       string
	Port     int
	Protocol string
	Service  string
	Product  string
}

func NewRunner(options *Options) (*Runner, error) {
	runner := &Runner{
		options: options,
	}
	runner.hostChan = make(chan *net.IPNet)
	runner.hostDiscoveryChan = make(chan *net.IPNet)
	runner.hostStrChan = make(chan string)

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
	runner.Scanner = scanner

	runner.Scanner.Ports, err = ParsePorts(options)
	if err != nil {
		return runner, err
	}

	if runner.options.ChooseRandomPorts {
		sliceutil.RandSlice(runner.Scanner.Ports)
	}

	runner.wgscan = sizedwaitgroup.New(runner.options.RateLimit)
	runner.ticker = time.NewTicker(time.Second / time.Duration(runner.options.RateLimit))

	return runner, err
}

func (runner *Runner) Run() error {
	defer runner.Close()

	if privileges.IsPrivileged && runner.options.ScanType == SynScan {
		err := runner.Scanner.SetupHandlers()
		if err != nil {
			return err
		}
		runner.BackgroundWorkers()
	}

	go runner.PreprocessingHosts()

	return nil
}

func (r *Runner) BackgroundWorkers() {
	r.Scanner.StartWorkers()
}

func (runner *Runner) Start() {
	rand.Seed(time.Now().UnixNano())

	starttime := time.Now()

	isSynScanType := runner.options.isSynScan()

	gologger.Print().Msgf(
		"Initiating %s Scan (Package to send %d times/s). Starting Aries %s at %s\n",
		runner.options.scanType(),
		runner.options.RateLimit,
		Version,
		dateutil.GetNowFullDateTime(),
	)

	// Host Discovery & Port Scan
	if !runner.options.SkipHostDiscovery {
		tempHosts, err := os.CreateTemp("", "aries-temp-discovery-hosts-*")
		if err != nil {
			return
		}
		defer tempHosts.Close()

		gologger.Print().Msg("Running Host Discovery")

		for cidr := range runner.hostDiscoveryChan {
			ipStream, _ := mapcidr.IPAddressesAsStream(cidr.String())
			for ip := range ipStream {
				runner.wgscan.Add()

				go func(ip string) {
					<-runner.ticker.C
					defer runner.wgscan.Done()

					disIp := scan.DiscoveredHost(ip)
					if len(disIp) > 0 {
						go atomic.AddInt32(&runner.HostCount, 1)
						runner.Scanner.ScanResults.AddDiscoveryIp(ip)
						fmt.Fprintf(tempHosts, "%s\n", disIp)
					}
				}(ip)
			}
		}
		runner.wgscan.Wait()

		if runner.HostCount == 0 {
			gologger.Print().Msg("\"-Pn\" treat all hosts as online -- skip host discovery")
		}

		f, err := os.Open(tempHosts.Name())
		if err != nil {
			return
		}
		defer f.Close()

		s := bufio.NewScanner(f)
		for s.Scan() {
			ip := s.Text()

			host := ip
			if dt, err := runner.Scanner.IPRanger.GetHostsByIP(ip); err == nil && len(dt) > 0 {
				host = dt[0]
			}

			runner.Pavo(host, ip)

			for _, port := range runner.Scanner.Ports {
				if runner.Scanner.ScanResults.HasSkipped(ip) {
					continue
				}
				runner.Scanner.Phase.Set(scan.Scan)
				if isSynScanType {
					runner.handleHostPortSyn(ip, port)
				} else {
					runner.wgscan.Add()
					go runner.connectScan(host, ip, port)
				}
			}
		}
	}

	// Skip Host Discovery
	if runner.options.SkipHostDiscovery {
		for cidr := range runner.hostChan {
			ipStream, _ := mapcidr.IPAddressesAsStream(cidr.String())
			for ip := range ipStream {
				go atomic.AddInt32(&runner.HostCount, 1)

				host := ip
				if dt, err := runner.Scanner.IPRanger.GetHostsByIP(ip); err == nil && len(dt) > 0 {
					host = dt[0]
				}

				runner.Pavo(host, ip)

				for _, port := range runner.Scanner.Ports {
					if runner.Scanner.ScanResults.HasSkipped(ip) {
						continue
					}
					runner.Scanner.Phase.Set(scan.Scan)
					if isSynScanType {
						runner.handleHostPortSyn(ip, port)
					} else {
						runner.wgscan.Add()
						go runner.connectScan(host, ip, port)
					}
				}

			}
		}
	}

	runner.wgscan.Wait()

	runner.Scanner.Phase.Set(scan.Done)

	if runner.options.NmapServiceProbes {
		runner.NmapServiceProbes()
	}

	runner.handleOutput()

	runner.WriteOutput()

	gologger.Print().Msgf("%d IP addresses (Found %d hosts %d ports up) scanned in %s. Aries finished at %s\n",
		runner.HostCount,
		runner.Scanner.ScanResults.Len(),
		runner.portCount(),
		strings.Split(time.Since(starttime).String(), ".")[0]+"s",
		dateutil.GetNowFullDateTime(),
	)
}

func (runner *Runner) Pavo(host, ip string) {
	if runner.Scanner.ScanResults.HasSkipped(ip) || iptuil.IsInternal(ip) {
		return
	}
	if rst, err := runner.Scanner.PavoPortScan(ip, 1000); err == nil {
		for _, r := range rst.Result {
			rstport, _ := strconv.Atoi(r.Port)
			pport := &port.Port{Port: rstport, Service: r.Server, Protocol2: r.Protocol}

			if runner.Scanner.ScanResults.IPHasPort(ip, pport) {
				continue
			}

			runner.Scanner.ScanResults.AddPort(ip, pport)
			runner.OnResult(Result{Host: host, IP: ip, Port: rstport, Protocol: r.Protocol, Service: r.Server})
		}
	}
}

func (r *Runner) portCount() int32 {
	if r.options.isSynScan() {
		return r.Scanner.PortCount
	}
	return r.PortCount
}

func (r *Runner) handleHostPortSyn(ip string, p *port.Port) {
	<-r.ticker.C
	if r.Scanner.ScanResults.IPHasPort(ip, p) {
		return
	}
	r.Scanner.EnqueueTCP(ip, scan.Syn, p)
}

func (runner *Runner) connectScan(host, ip string, port *port.Port) {

	defer runner.wgscan.Done()

	if runner.Scanner.ScanResults.IPHasPort(ip, port) {
		return
	}

	<-runner.ticker.C

	open, err := runner.Scanner.ConnectPort(ip, port, time.Duration(runner.options.Timeout)*time.Millisecond)
	if open && err == nil {
		if isWindows() && (port.Port == 110 || port.Port == 25) {
			return
		}
		// gologger.Print().Msgf("Discovered open port %d/%s on %s(%s)\n", port.Port, port.Protocol, host, ip)

		runner.Scanner.ScanResults.AddPort(ip, port)

		runner.OnResult(Result{Host: host, IP: ip, Port: port.Port})

		go atomic.AddInt32(&runner.PortCount, 1)
	}
}

// Close runner instance
func (runner *Runner) Close() {
	os.RemoveAll(runner.tempHostFile)
}

func (r *Runner) NmapServiceProbes() {

	r.Scanner.Phase.Set(scan.Scan)
	defer r.Scanner.Phase.Set(scan.Done)

	if r.Scanner.ScanResults.Len() == 0 {
		return
	}

	gologger.Print().Msg("Running Nmap Service Probes")

	var swg sync.WaitGroup
	limiter := time.NewTicker(time.Second / time.Duration(r.options.RateLimit))

	verifiedResult := result.NewResult()
	verifiedResult.SetDiscoveryIPS(r.Scanner.ScanResults.GetDiscoveryIPs())

	for hostResult := range r.Scanner.ScanResults.GetIPsPorts() {
		<-limiter.C
		swg.Add(1)

		go func(hostResult *result.HostResult) {
			defer swg.Done()

			results := r.Scanner.NmapServiceProbesScan(hostResult.IP, hostResult.Ports)
			verifiedResult.SetPorts(hostResult.IP, results)

		}(hostResult)
	}

	r.Scanner.ScanResults = verifiedResult

	swg.Wait()
}
