package port

import (
	"fmt"

	"github.com/zan8in/aries/pkg/protocol"
)

type Port struct {
	Port         int
	Protocol     protocol.Protocol
	TLS          bool
	Service      string
	Protocol2    string
	ProbeProduct string
	Version      string
}

func (p *Port) String() string {
	return fmt.Sprintf("%d-%d-%v", p.Port, p.Protocol, p.TLS)
}
