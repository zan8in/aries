package aries

import (
	"github.com/zan8in/aries/pkg/privilege"
	"github.com/zan8in/goflags"
	"github.com/zan8in/gologger"
)

type Options struct {
	Host           goflags.StringSlice // Host is the single host or comma-separated list of hosts to find ports for
	HostsFile      string              // HostsFile is the file containing list of hosts to find port for
	ExcludeIps     string              // Ips or cidr to be excluded from the scan
	ExcludeIpsFile string              // File containing Ips or cidr to exclude from the scan
	Ports          string              // Ports is the ports to use for enumeration
	PortsFile      string              // PortsFile is the file containing ports to use for enumeration
	ExcludePorts   string              // ExcludePorts is the list of ports to exclude from enumeration
	TopPorts       string              // Tops ports to scan

	Retries   int                 // Retries is the number of retries for the port
	Threads   int                 // Internal worker threads
	RateLimit int                 // RateLimit is the rate of port scan requests
	Timeout   int                 // Timeout is the seconds to wait for ports to respond
	IPVersion goflags.StringSlice // IP Version to use while resolving hostnames
	ScanType  string              // Scan Type
}

func ParseOptions() *Options {

	options := &Options{}

	flagSet := goflags.NewFlagSet()
	flagSet.SetDescription(`Aries`)

	flagSet.CreateGroup("input", "Input",
		flagSet.StringSliceVarP(&options.Host, "h", "host", nil, "hosts to scan ports for (comma-separated)", goflags.NormalizedStringSliceOptions),
		flagSet.StringVarP(&options.HostsFile, "hf", "host-file", "", "list of hosts to scan ports (file)"),
		flagSet.StringVarP(&options.ExcludeIps, "eh", "exclude-hosts", "", "hosts to exclude from the scan (comma-separated)"),
		flagSet.StringVarP(&options.ExcludeIpsFile, "ef", "exclude-file", "", "list of hosts to exclude from scan (file)"),
	)

	flagSet.CreateGroup("port", "Port",
		flagSet.StringVarP(&options.Ports, "p", "port", "", "ports to scan (80,443, 100-200)"),
		flagSet.StringVarP(&options.TopPorts, "tp", "top-ports", "", "top ports to scan (default 100)"),
		flagSet.StringVarP(&options.ExcludePorts, "ep", "exclude-ports", "", "ports to exclude from scan (comma-separated)"),
		flagSet.StringVarP(&options.PortsFile, "pf", "ports-file", "", "list of ports to scan (file)"),
	)

	flagSet.CreateGroup("rate-limit", "Rate-limit",
		flagSet.IntVar(&options.Threads, "c", 25, "general internal worker threads"),
		flagSet.IntVar(&options.RateLimit, "rate", DefaultRateSynScan, "packets to send per second"),
	)

	flagSet.CreateGroup("config", "Configuration",
		flagSet.StringVarP(&options.ScanType, "s", "scan-type", SynScan, "type of port scan (SYN/CONNECT)"),
		flagSet.StringSliceVarP(&options.IPVersion, "iv", "ip-version", nil, "ip version to scan of hostname (4,6) - (default 4)", goflags.NormalizedStringSliceOptions),
	)

	flagSet.CreateGroup("optimization", "Optimization",
		flagSet.IntVar(&options.Retries, "retries", DefaultRetriesSynScan, "number of retries for the port scan"),
		flagSet.IntVar(&options.Timeout, "timeout", DefaultPortTimeoutSynScan, "millisecond to wait before timing out"),
	)

	_ = flagSet.Parse()

	err := options.validateOptions()
	if err != nil {
		gologger.Fatal().Msgf("Program exiting: %s\n", err)
	}

	return options
}

func (options *Options) validateOptions() (err error) {

	return err
}

func (options *Options) isSynScan() bool {
	return isOSSupported() && privilege.IsPrivileged && options.ScanType == SynScan
}
