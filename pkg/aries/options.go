package aries

import (
	"fmt"
	"net"
	"runtime"

	"github.com/pkg/errors"
	"github.com/zan8in/aries/pkg/privileges"
	"github.com/zan8in/aries/pkg/util/fileutil"
	"github.com/zan8in/goflags"
	"github.com/zan8in/gologger"
	"github.com/zan8in/gologger/levels"
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

	Retries           int                 // Retries is the number of retries for the port
	Threads           int                 // Internal worker threads
	RateLimit         int                 // RateLimit is the rate of port scan requests
	Timeout           int                 // Timeout is the seconds to wait for ports to respond
	IPVersion         goflags.StringSlice // IP Version to use while resolving hostnames
	ScanType          string              // Scan Type
	Debug             bool                // Prints out debug information
	Interface         string              // Interface to use for TCP packets
	Output            string              // Output is the file to write found ports to.
	NmapServiceProbes bool                // Nmap Service Probes
}

func ParseOptions() *Options {

	ShowBanner()

	options := &Options{}

	flagSet := goflags.NewFlagSet()
	flagSet.SetDescription(`Aries`)

	flagSet.CreateGroup("input", "Input",
		flagSet.StringSliceVarP(&options.Host, "t", "target", nil, "hosts to scan ports for (comma-separated)", goflags.NormalizedStringSliceOptions),
		flagSet.StringVarP(&options.HostsFile, "T", "target-file", "", "list of hosts to scan ports (file)"),
		flagSet.StringVarP(&options.ExcludeIps, "eh", "exclude-hosts", "", "hosts to exclude from the scan (comma-separated)"),
		flagSet.StringVarP(&options.ExcludeIpsFile, "ef", "exclude-file", "", "list of hosts to exclude from scan (file)"),
	)

	flagSet.CreateGroup("port", "Port",
		flagSet.StringVarP(&options.Ports, "p", "port", "", "ports to scan (80,443, 100-200)"),
		flagSet.StringVarP(&options.TopPorts, "tp", "top-ports", "", "top ports to scan, support: mini, 100, 1000, full, database, hotel, iot, ics (default 100)"),
		flagSet.StringVarP(&options.ExcludePorts, "ep", "exclude-ports", "", "ports to exclude from scan (comma-separated)"),
		flagSet.StringVarP(&options.PortsFile, "pf", "ports-file", "", "list of ports to scan (file)"),
	)

	flagSet.CreateGroup("rate-limit", "Rate-limit",
		flagSet.IntVar(&options.Threads, "c", 25, "general internal worker threads"),
		flagSet.IntVar(&options.RateLimit, "rate", DefaultRateSynScan, "packets to send per second"),
	)

	flagSet.CreateGroup("config", "Configuration",
		flagSet.StringVarP(&options.ScanType, "s", "scan-type", SynScan, "type of port scan (SYN/CONNECT)"),
		flagSet.BoolVar(&options.NmapServiceProbes, "A", false, "nmap service probes"),
		flagSet.StringSliceVarP(&options.IPVersion, "iv", "ip-version", nil, "ip version to scan of hostname (4,6) - (default 4)", goflags.NormalizedStringSliceOptions),
		flagSet.StringVarP(&options.Interface, "i", "interface", "", "network Interface to use for port scan"),
	)

	flagSet.CreateGroup("output", "Output",
		flagSet.StringVarP(&options.Output, "output", "o", "", "file to write output to (optional), support format: txt,csv,json"),
	)

	flagSet.CreateGroup("optimization", "Optimization",
		flagSet.IntVar(&options.Retries, "retries", DefaultRetriesSynScan, "number of retries for the port scan"),
		flagSet.IntVar(&options.Timeout, "timeout", DefaultPortTimeoutSynScan, "millisecond to wait before timing out"),
	)

	flagSet.CreateGroup("debug", "Debug",
		flagSet.BoolVar(&options.Debug, "debug", false, "display debugging information"),
	)

	_ = flagSet.Parse()

	err := options.validateOptions()
	if err != nil {
		gologger.Fatal().Msgf("Program exiting: %s\n", err)
	}

	return options
}

var (
	errNoInputList    = errors.New("no input list provided")
	errOutputFielType = errors.New("output file type error, support txt, json, csv")
	errZeroValue      = errors.New("cannot be zero")
	errTwoOutputMode  = errors.New("both json and csv mode specified")
)

func (options *Options) validateOptions() (err error) {

	if options.Host == nil && options.HostsFile == "" {
		return errNoInputList
	}

	if options.Timeout == 0 {
		return errors.Wrap(errZeroValue, "timeout")
	} else if !privileges.IsPrivileged && options.Timeout == DefaultPortTimeoutSynScan {
		options.Timeout = DefaultPortTimeoutConnectScan
	}

	if options.RateLimit <= 0 {
		return errors.Wrap(errZeroValue, "rate")
	} else if !privileges.IsPrivileged && options.RateLimit == DefaultRateSynScan {
		options.RateLimit = DefaultRateConnectScan
		options.autoChangeRateLimit()
	}

	if !privileges.IsPrivileged && options.Retries == DefaultRetriesSynScan {
		options.Retries = DefaultRetriesConnectScan
	}

	if options.Interface != "" {
		if _, err := net.InterfaceByName(options.Interface); err != nil {
			return fmt.Errorf("interface %s not found", options.Interface)
		}
	}

	if options.Debug {
		gologger.DefaultLogger.SetMaxLevel(levels.LevelDebug)
	}

	if len(options.Output) > 0 {
		if err := checkOutput(options.Output); err != nil {
			return err
		}
	}

	return err
}

func (options *Options) autoChangeRateLimit() {
	NumCPU := runtime.NumCPU()
	options.RateLimit = NumCPU * 50

	// if options.Ports == "1-65535" || options.Ports == "-" || strings.ToLower(options.TopPorts) == "full" {
	// 	// linux(root) + syn = cpu num * 50
	// 	// eg: 4 core = ratelimit 200
	// 	if options.isSynScan() {
	// 		options.RateLimit = NumCPU * 50
	// 	}
	// 	if options.isConnectScan() {
	// 		options.RateLimit = NumCPU * 100
	// 	}
	// }
}

func checkOutput(output string) error {
	fileType := fileutil.FileExt(output)
	switch fileType {
	case fileutil.FILE_TXT:
		return nil
	case fileutil.FILE_JSON:
		return nil
	case fileutil.FILE_CSV:
		return nil
	default:
		return errOutputFielType
	}
}

func (options *Options) isSynScan() bool {
	return isPrivileged() && options.ScanType == SynScan
}

func (options *Options) isConnectScan() bool {
	return options.ScanType == ConnectScan
}

func (options *Options) scanType() string {
	if options.isSynScan() {
		return "SYN"
	}
	return "CONNECT"
}
