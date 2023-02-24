package aries

import (
	"github.com/zan8in/goflags"
	"github.com/zan8in/gologger"
)

type Options struct {
	Ports        string // Ports is the ports to use for enumeration
	PortsFile    string // PortsFile is the file containing ports to use for enumeration
	ExcludePorts string // ExcludePorts is the list of ports to exclude from enumeration
	TopPorts     string // Tops ports to scan
}

func ParseOptions() *Options {

	options := &Options{}

	flagSet := goflags.NewFlagSet()
	flagSet.SetDescription(`Aries`)

	flagSet.CreateGroup("port", "Port",
		flagSet.StringVarP(&options.Ports, "p", "port", "", "ports to scan (80,443, 100-200)"),
		flagSet.StringVarP(&options.TopPorts, "tp", "top-ports", "", "top ports to scan (default 100)"),
		flagSet.StringVarP(&options.ExcludePorts, "ep", "exclude-ports", "", "ports to exclude from scan (comma-separated)"),
		flagSet.StringVarP(&options.PortsFile, "pf", "ports-file", "", "list of ports to scan (file)"),
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
