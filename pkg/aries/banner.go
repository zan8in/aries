package aries

import (
	"github.com/zan8in/gologger"
)

var Version = "0.1.2"

func ShowBanner() {
	gologger.Print().Msgf("\n|||\tA R I E S\t|||\t%s\n\n", Version)
}
