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
		gologger.Print().Msgf("%s:%d\n", r.Host, r.Port)
	}

	err = runner.Run()
	if err != nil {
		gologger.Fatal().Msg(err.Error())
	}

	runner.Start()

}
