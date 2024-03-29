package aries

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/zan8in/aries/pkg/port"
	"github.com/zan8in/aries/pkg/util/dateutil"
	"github.com/zan8in/aries/pkg/util/fileutil"
	"github.com/zan8in/gologger"
	fileutil2 "github.com/zan8in/pins/file"
)

type OutputResult struct {
	Host    string     `json:"host,omitempty" csv:"host"`
	IP      string     `json:"ip,omitempty" csv:"ip"`
	Port    *port.Port `json:"port" csv:"port"`
	IsCDNIP bool       `json:"cdn,omitempty" csv:"cdn"`
}

func (r *Runner) handleOutput() {
	switch {
	case r.Scanner.ScanResults.HasIPsPorts():
		for hostResult := range r.Scanner.ScanResults.GetIPsPorts() {
			dt, err := r.Scanner.IPRanger.GetHostsByIP(hostResult.IP)
			if err != nil {
				continue
			}
			for _, host := range dt {
				hostname := host
				if host == "ip" {
					hostname = hostResult.IP
				}
				gologger.Print().Msgf(
					"Found %d ports on host %s (%s)\n",
					len(hostResult.Ports),
					hostname,
					hostResult.IP,
				)
				for _, p := range hostResult.Ports {
					gologger.Silent().Msgf(
						"%s:%d\t%s\t%s\t%s %s\n",
						hostResult.IP,
						p.Port,
						p.Protocol2,
						p.Service,
						p.ProbeProduct,
						p.Version,
					)
				}

			}
		}
	}
}

func (r *Runner) WriteOutput() {

	if r.Scanner.ScanResults.IsEmpty() {
		return
	}

	var (
		file          *os.File
		fileDsicovery *os.File
		output        string
		err           error
		fileType      uint8
		csvutil       *csv.Writer
	)

	output = r.options.Output

	if len(r.options.Output) == 0 {
		if len(r.options.Host) > 0 {
			output = r.options.Host[0] + ".csv"
		} else if len(r.options.HostsFile) > 0 {
			output = fileutil.GetFilename(r.options.HostsFile) + ".csv"
		} else {
			output = "output-" + dateutil.GetTimeFormat() + ".csv"
		}
		output = strings.ReplaceAll(output, "/", "-")
	}

	fileType = fileutil.FileExt(output)

	if fileutil.FileOrFolderExists(output) {
		output = fileutil.CombineNewFilename(output, dateutil.GetTimeFormat(), "-")
	}

	outputFolder := filepath.Dir(output)
	if fileutil.FolderExists(outputFolder) {
		mkdirErr := os.MkdirAll(outputFolder, 0700)
		if mkdirErr != nil {
			gologger.Error().Msgf("Could not create output folder %s: %s\n", outputFolder, mkdirErr)
			return
		}
	}

	file, err = os.Create(output)
	if err != nil {
		gologger.Error().Msgf("Could not create file %s: %s\n", output, err)
		return
	}
	defer file.Close()

	switch fileType {
	case fileutil.FILE_CSV:
		csvutil = csv.NewWriter(file)
		file.WriteString("\xEF\xBB\xBF")
		csvutil.Write([]string{"Host", "IP", "PORT", "Protocol", "Service", "Product"})
	case fileutil.FILE_JSON:
		fileutil.BufferWriteAppend(file, "[")
	}

	if r.Scanner.ScanResults.HasIPsPorts() {
		for hostResult := range r.Scanner.ScanResults.GetIPsPorts() {
			dt, err := r.Scanner.IPRanger.GetHostsByIP(hostResult.IP)
			if err != nil {
				continue
			}
			for _, host := range dt {
				hostname := host
				if host == "ip" {
					hostname = hostResult.IP
				}

				for _, p := range hostResult.Ports {
					or := &OutputResult{Host: hostname, IP: hostResult.IP}
					or.Port = p

					switch fileType {
					case fileutil.FILE_TXT:
						fileutil.BufferWriteAppend(file, or.TXT())
					case fileutil.FILE_JSON:
						b, marshallErr := or.JSON()
						if marshallErr != nil {
							continue
						}
						fileutil.BufferWriteAppend(file, string(b)+",")
					case fileutil.FILE_CSV:
						csvutil.Write(or.CSV())
					}
				}

			}
			switch fileType {
			case fileutil.FILE_CSV:
				csvutil.Flush()
			}
		}

		switch fileType {
		case fileutil.FILE_JSON:
			fileutil.BufferWriteAppend(file, "]")
			fileutil2.CoverFile(output, ",]", "]")
		}

		gologger.Print().Msgf("generate scan result report \"%s\"\n", output)
	}

	if r.Scanner.ScanResults.HasDiscoveryIPS() {
		output = strings.ReplaceAll(output, ".csv", "-host-discovery.txt")
		output = strings.ReplaceAll(output, ".json", "-host-discovery.txt")
		fileDsicovery, err = os.Create(output)
		if err != nil {
			gologger.Error().Msgf("Could not create file %s: %s\n", output, err)
			return
		}
		defer fileDsicovery.Close()

		for ip := range r.Scanner.ScanResults.GetDiscoveryIPs() {
			fileutil.BufferWriteAppend(fileDsicovery, ip+"\n")
		}
		gologger.Print().Msgf("generate host discovery result report \"%s\"\n", output)
	}

}

func (or *OutputResult) JSON() ([]byte, error) {
	return json.Marshal(or)
}

func (or *OutputResult) TXT() string {
	if or.Host == "ip" {
		return fmt.Sprintf("%s:%d\t%s\n", or.IP, or.Port.Port, cndName(or.IsCDNIP))
	}
	return fmt.Sprintf("%s:%d\t%s\n", or.Host, or.Port.Port, cndName(or.IsCDNIP))
}

func (or *OutputResult) CSV() []string {
	if or.Host == "ip" {
		or.Host = or.IP
	}
	// "Host", "IP", "PORT", "Protocol", "Product", "CDN", "URL", "Title"
	var (
		host string
		ip   string
	)

	host = or.Host + ":" + strconv.Itoa(or.Port.Port)
	ip = or.IP + ":" + strconv.Itoa(or.Port.Port)

	return []string{
		host,
		ip,
		strconv.Itoa(or.Port.Port),
		or.Port.Protocol2,
		or.Port.Service,
		or.Port.ProbeProduct + or.Port.Version,
	}
}

func cndName(b bool) string {
	if b {
		return "CDN"
	}
	return ""
}
