package api

import (
	"github.com/zan8in/aries/pkg/aries"
	"github.com/zan8in/gologger"
)

func PortScanner(host string, limit int) {
	options := aries.NewOptions(aries.Options{
		Host:              []string{host},
		RateLimit:         limit,
		SkipHostDiscovery: true,
		TopPorts:          "100",
		Retries:           aries.DefaultRetriesSynScan,
		Timeout:           aries.DefaultPortTimeoutSynScan,
	})

	runner, err := aries.NewRunner(options)
	if err != nil {
		gologger.Fatal().Msg(err.Error())
	}

	err = runner.Run()
	if err != nil {
		gologger.Fatal().Msg(err.Error())
	}

	runner.StartApi()

}
