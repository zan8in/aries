package main

import (
	"github.com/zan8in/aries/pkg/aries"
	"github.com/zan8in/gologger"
)

func main() {

	options := aries.ParseOptions()
	ports, err := aries.ParsePorts(options)
	if err != nil {
		gologger.Fatal().Msg(err.Error())
	}
	gologger.Info().Msgf("%v", ports)
}
