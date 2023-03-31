package aries

import (
	"math/rand"
	"sync/atomic"
	"time"

	"github.com/zan8in/aries/pkg/scan"
	"github.com/zan8in/aries/pkg/util/mapcidr"
)

func NewOptions(options Options) *Options {
	return &options
}

func (runner *Runner) StartApi() {
	rand.Seed(time.Now().UnixNano())

	isSynScanType := runner.options.isSynScan()

	// Skip Host Discovery
	if runner.options.SkipHostDiscovery {
		for cidr := range runner.hostChan {
			ipStream, _ := mapcidr.IPAddressesAsStream(cidr.String())
			for ip := range ipStream {
				go atomic.AddInt32(&runner.HostCount, 1)

				for _, port := range runner.scanner.Ports {
					if runner.scanner.ScanResults.HasSkipped(ip) {
						continue
					}
					runner.scanner.Phase.Set(scan.Scan)
					if isSynScanType {
						runner.handleHostPortSyn(ip, port)
					} else {
						runner.wgscan.Add()
						go runner.connectScan(ip, port)
					}
				}

			}
		}
	}

	runner.wgscan.Wait()
}
