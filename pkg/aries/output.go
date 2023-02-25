package aries

import (
	"github.com/zan8in/aries/pkg/result"
	"github.com/zan8in/gologger"
)

func (runner *Runner) output(scanResult *result.Result) {
	for hostResult := range scanResult.GetIPsPorts() {
		gologger.Info().Msgf("Found %d ports on host %s (%s)\n", len(hostResult.Ports), scanResult.GetHost(hostResult.IP), hostResult.IP)
		for _, port := range hostResult.Ports {
			gologger.Silent().Msgf("%s:%d\n", hostResult.IP, port)
		}
	}
}
