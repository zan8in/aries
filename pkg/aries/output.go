package aries

import (
	"github.com/zan8in/aries/pkg/result"
	"github.com/zan8in/gologger"
)

func (runner *Runner) output(scanResult *result.Result) {
	for hostResult := range scanResult.GetIPsPorts() {
		gologger.Info().Msgf("Found %d ports on host %s (%s)\n", len(hostResult.Ports), hostResult.IP, hostResult.IP)
		for _, port := range hostResult.Ports {
			gologger.Silent().Msgf("%s:%d\n", hostResult.IP, port.Port)
		}
	}
}

func (r *Runner) handleOutput(scanResults *result.Result) {

	// In case the user has given an output file, write all the found
	// ports to the output file.

	switch {
	case scanResults.HasIPsPorts():
		for hostResult := range scanResults.GetIPsPorts() {
			dt, err := r.scanner.IPRanger.GetHostsByIP(hostResult.IP)
			if err != nil {
				continue
			}
			for _, host := range dt {
				if host == "ip" {
					host = hostResult.IP
				}
				gologger.Info().Msgf("Found %d ports on host %s (%s)\n", len(hostResult.Ports), host, hostResult.IP)
				for _, p := range hostResult.Ports {
					gologger.Silent().Msgf("%s:%d\n", hostResult.IP, p.Port)
				}

			}
		}
	case scanResults.HasIPS():
		for hostIP := range scanResults.GetIPs() {
			dt, err := r.scanner.IPRanger.GetHostsByIP(hostIP)
			if err != nil {
				continue
			}
			for _, host := range dt {
				if host == "ip" {
					host = hostIP
				}
				gologger.Info().Msgf("Found alive host %s (%s)\n", host, hostIP)

			}
		}
	}

}
