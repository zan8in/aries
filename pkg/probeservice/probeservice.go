package probeservice

import (
	"regexp"
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
		Probe.NmapServiceMap.Store(port, FixProtocol(protocol))
	}
}

var regexpFirstNum = regexp.MustCompile(`^\d`)

func FixProtocol(oldProtocol string) string {
	//进行最后输出修饰
	if oldProtocol == "ssl/http" {
		return "https"
	}
	if oldProtocol == "http-proxy" {
		return "http"
	}
	if oldProtocol == "ms-wbt-server" {
		return "rdp"
	}
	if oldProtocol == "microsoft-ds" {
		return "smb"
	}
	if oldProtocol == "netbios-ssn" {
		return "netbios"
	}
	if oldProtocol == "oracle-tns" {
		return "oracle"
	}
	if oldProtocol == "msrpc" {
		return "rpc"
	}
	if oldProtocol == "ms-sql-s" {
		return "mssql"
	}
	if oldProtocol == "domain" {
		return "dns"
	}
	if oldProtocol == "svnserve" {
		return "svn"
	}
	if oldProtocol == "ibm-db2" {
		return "db2"
	}
	if oldProtocol == "socks-proxy" {
		return "socks5"
	}
	if len(oldProtocol) > 4 {
		if oldProtocol[:4] == "ssl/" {
			return oldProtocol[4:] + "-ssl"
		}
	}
	if regexpFirstNum.MatchString(oldProtocol) {
		oldProtocol = "S" + oldProtocol
	}
	oldProtocol = strings.ReplaceAll(oldProtocol, "_", "-")
	return oldProtocol
}
