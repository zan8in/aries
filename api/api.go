package api

import (
	"github.com/zan8in/aries/pkg/aries"
	"github.com/zan8in/gologger"
	"github.com/zan8in/gologger/levels"
)

type Result struct {
	Host    string
	IP      string
	Port    int
	Service string
	Product string
}

func PortScanner(host, top string, limit int) ([]Result, error) {
	gologger.DefaultLogger.SetMaxLevel(levels.LevelFatal)
	var result []Result
	var err error

	if len(top) == 0 {
		top = "100"
	}
	options := aries.NewOptions(aries.Options{
		Host:              []string{host},
		RateLimit:         limit,
		SkipHostDiscovery: true,
		TopPorts:          top,
		Retries:           aries.DefaultRetriesSynScan,
		Timeout:           aries.DefaultPortTimeoutSynScan,
	})

	runner, err := aries.NewRunner(options)
	if err != nil {
		return result, err
	}

	if err = runner.Run(); err != nil {
		return result, err
	}

	runner.StartApi()

	runner.NmapServiceProbes()

	switch {
	case runner.Scanner.ScanResults.HasIPsPorts():
		for hostResult := range runner.Scanner.ScanResults.GetIPsPorts() {
			dt, err := runner.Scanner.IPRanger.GetHostsByIP(hostResult.IP)
			if err != nil {
				continue
			}
			for _, host := range dt {
				hostname := host
				if host == "ip" {
					hostname = hostResult.IP
				}

				for _, p := range hostResult.Ports {
					result = append(result, Result{Host: hostname, IP: hostResult.IP, Port: p.Port, Service: p.Service, Product: p.ProbeProduct})
				}

			}
		}
	}

	return result, nil
}
