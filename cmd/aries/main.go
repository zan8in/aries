package main

import (
	"github.com/zan8in/aries/pkg/aries"
	"github.com/zan8in/gologger"
)

func main() {

	options := aries.ParseOptions()

	runner, err := aries.NewRunner(options)
	if err != nil {
		gologger.Fatal().Msg(err.Error())
	}

	err = runner.Run()
	if err != nil {
		gologger.Fatal().Msg(err.Error())
	}

	// runner.Listener()

	// runner.ScanHost()

	// scanner, err := aries.NewScanner(options)
	// if err != nil {
	// 	gologger.Fatal().Msg(err.Error())
	// }

	// scanner.ConnectScan()

	// go scanner.StartWorkers()
	// scanner.ScanSyn("192.168.66.80")

	// time.Sleep(10 * time.Second)

	// for hostResult := range scanner.ScanResults.GetIPsPorts() {
	// 	gologger.Info().Msgf("%s:%d", hostResult.IP, hostResult.Ports)
	// }
}
