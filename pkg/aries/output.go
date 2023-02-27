package aries

import (
	"github.com/zan8in/aries/pkg/probeservice"
	"github.com/zan8in/aries/pkg/result"
	"github.com/zan8in/gologger"
)

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
					serviceName := ""
					service, ok := probeservice.Probe.NmapServiceMap.Load(p.Port)
					if ok {
						serviceName = service.(string)
					}
					gologger.Silent().Msgf("%s:%d\t%s\n", hostResult.IP, p.Port, serviceName)
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
