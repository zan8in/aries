package api

import (
	"github.com/remeh/sizedwaitgroup"
	"github.com/zan8in/aries/pkg/aries"
	"github.com/zan8in/aries/pkg/scan"
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

type OnResultCallback func(r Result)

var OnResult OnResultCallback

func PortScanner(targets []string, top string, limit int) ([]Result, error) {
	gologger.DefaultLogger.SetMaxLevel(levels.LevelFatal)
	var result []Result
	var err error

	if len(top) == 0 {
		top = "100"
	}

	options := aries.NewOptions(aries.Options{
		Host:              targets,
		RateLimit:         limit,
		SkipHostDiscovery: true,
		TopPorts:          top,
		Retries:           aries.DefaultRetriesSynScan,
		Timeout:           aries.DefaultPortTimeoutSynScan,
	})

	if limit == 0 {
		options.AutoChangeRateLimit()
	}

	runner, err := aries.NewRunner(options)
	if err != nil {
		return result, err
	}

	swg := sizedwaitgroup.New(10)
	runner.OnResult = func(r aries.Result) {
		swg.Add()
		rst := Result{Host: r.Host, Port: r.Port, IP: r.IP}
		go func(rst Result) {
			defer swg.Done()
			service, probeProduct, _ := scan.ServiceScan(rst.IP, rst.Port)
			rst.Service = service
			rst.Product = probeProduct
			OnResult(rst)
		}(rst)
	}

	if err = runner.Run(); err != nil {
		return result, err
	}

	runner.StartApi()

	swg.Wait()

	return result, nil
}
