package main

import (
	"time"

	"github.com/zan8in/aries/pkg/aries"
	"github.com/zan8in/gologger"
)

func main() {

	options := aries.ParseOptions()

	_, err := aries.NewRunner(options)
	if err != nil {
		gologger.Fatal().Msg(err.Error())
	}

	// runner.ScanHost()

	time.Sleep(10 * time.Second)

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
