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

	runner.OnResult = func(r aries.Result) {
		gologger.Print().Msgf("Discovered open port %d on (%s) %s %s %s\n", r.Port, r.Host, r.IP, r.Protocol, r.Service)
	}

	err = runner.Run()
	if err != nil {
		gologger.Fatal().Msg(err.Error())
	}

	runner.Start()

}
