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
	ProbeProduct string
	Title        string
	Http         string
}

func (p *Port) String() string {
	return fmt.Sprintf("%d-%d-%v", p.Port, p.Protocol, p.TLS)
}
