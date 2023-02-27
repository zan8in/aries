package probeservice

import (
	"strconv"
	"strings"
	"sync"
)

type ProbeService struct {
	NmapServiceMap *sync.Map
}

var (
	Probe = &ProbeService{NmapServiceMap: &sync.Map{}}
)

func init() {
	initNmapService()
}

func initNmapService() {
	for _, line := range strings.Split(nmapServicesString, "\n") {
		index := strings.Index(line, "\t")
		v1 := line[:index]
		v2 := line[index+1:]
		port, _ := strconv.Atoi(v1)
		protocol := v2
		Probe.NmapServiceMap.Store(port, protocol)
	}
}
