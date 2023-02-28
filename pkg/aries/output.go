package aries

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"

	"github.com/zan8in/aries/pkg/port"
	"github.com/zan8in/aries/pkg/probeservice"
	"github.com/zan8in/aries/pkg/result"
	"github.com/zan8in/aries/pkg/util/fileutil"
	"github.com/zan8in/gologger"
)

type OutputResult struct {
	Host    string     `json:"host,omitempty" csv:"host"`
	IP      string     `json:"ip,omitempty" csv:"ip"`
	Port    *port.Port `json:"port" csv:"port"`
	IsCDNIP bool       `json:"cdn,omitempty" csv:"cdn"`
}

func (r *Runner) handleOutput(scanResults *result.Result) {
	switch {
	case scanResults.HasIPsPorts():
		for hostResult := range scanResults.GetIPsPorts() {
			dt, err := r.scanner.IPRanger.GetHostsByIP(hostResult.IP)
			if err != nil {
				continue
			}
			for _, host := range dt {
				hostname := host
				if host == "ip" {
					hostname = hostResult.IP
				}
				gologger.Info().Msgf("Found %d ports on host %s (%s)\n", len(hostResult.Ports), hostname, hostResult.IP)
				for _, p := range hostResult.Ports {
					gologger.Silent().Msgf("%s:%d\t%s\t%s\t%s\t%s\n", hostResult.IP, p.Port, p.Service, p.ProbeProduct, p.Http, p.Title)
				}

			}
		}
	}
}

func (r *Runner) WriteOutput(scanResults *result.Result) {
	if len(r.options.Output) == 0 {
		return
	}

	var (
		file     *os.File
		output   string
		err      error
		fileType uint8
		csvutil  *csv.Writer
	)

	output = r.options.Output
	fileType = fileutil.FileExt(r.options.Output)

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

	if fileType == fileutil.FILE_CSV {
		csvutil = csv.NewWriter(file)
		file.WriteString("\xEF\xBB\xBF")
		csvutil.Write([]string{"HOST", "IP", "PORT", "CDN", "HOST:PORT", "IP:PORT"})
	}

	switch {
	case scanResults.HasIPsPorts():
		for hostResult := range scanResults.GetIPsPorts() {
			dt, err := r.scanner.IPRanger.GetHostsByIP(hostResult.IP)
			if err != nil {
				continue
			}
			for _, host := range dt {
				hostname := host
				if host == "ip" {
					hostname = hostResult.IP
				}
				gologger.Info().Msgf("Found %d ports on host %s (%s)\n", len(hostResult.Ports), hostname, hostResult.IP)

				for _, p := range hostResult.Ports {
					or := &OutputResult{Host: host, IP: hostResult.IP}
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
						csvutil.Flush()
					}
					serviceName := ""
					service, ok := probeservice.Probe.NmapServiceMap.Load(p.Port)
					if ok {
						serviceName = service.(string)
					}
					gologger.Silent().Msgf("%s:%d\t%s\n", hostResult.IP, p.Port, serviceName)
				}

			}
		}
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
	return []string{or.Host, or.IP, strconv.Itoa(or.Port.Port), cndName(or.IsCDNIP), or.Host + ":" + strconv.Itoa(or.Port.Port), or.IP + ":" + strconv.Itoa(or.Port.Port)}
}

func cndName(b bool) string {
	if b {
		return "CDN"
	}
	return ""
}
