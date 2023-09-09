package ipranger

import "github.com/zan8in/aries/pkg/util/mapcidr"

type Stats struct {
	Hosts uint64
	IPS   uint64
	Ports uint64
}

func (s Stats) Total() uint64 {
	return s.Hosts + s.IPS
}

// Ips of a cidr
func Ips(cidr string) ([]string, error) {
	return mapcidr.IPAddresses(cidr)
}
