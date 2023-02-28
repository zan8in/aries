package probeservice

import (
	"embed"
	"fmt"
	"strings"

	"github.com/dlclark/regexp2"
)

//go:embed probes/*
var f embed.FS

type Nmap struct {
	NSP []NmapServiceProbes
}

type NmapServiceProbes struct {
	Service      string
	RegexString  string
	ProbeProduct string
}

var (
	NmapProbes = &Nmap{}
)

func Test() {
	str := "220 FileZilla Server 0.9.60 beta written by Tim Kosse (Tim.Kosse@gmx.de) Please visit http://sourceforge."

	fmt.Printf("Nmap Probes Len: %d\n", len(NmapProbes.NSP))
	nsp, ok := NmapRegex(str)
	if !ok {
		fmt.Println("未发现指纹")
		return
	}
	fmt.Println(nsp.Service, nsp.RegexString, nsp.ProbeProduct)

}

func NmapRegex(matchString string) (NmapServiceProbes, bool) {
	for _, regex := range NmapProbes.NSP {
		re := regexp2.MustCompile(regex.RegexString, 0)
		match, _ := re.MatchString(matchString)
		if match {
			return regex, match
		}
	}
	return NmapServiceProbes{}, false
}

func init() {
	InitNmapServiceProbes()
}

func InitNmapServiceProbes() {

	nmapServiceProbes, err := f.ReadFile("probes/nmap-service-probes")
	if err != nil {
		return
	}

	nmapServiceProbesString := repairNMAPString(string(nmapServiceProbes))

	lines := strings.Split(nmapServiceProbesString, "\n")

	for _, line := range lines {
		if !isCommand(line) {
			continue
		}

		service := strings.Split(line, " ")
		nsp := NmapServiceProbes{Service: service[1]}

		if strings.Index(line, "m|^") > 0 {
			regexString := strings.TrimSpace(line[strings.Index(line, "m|"):])[2:]
			len := strings.Index(regexString, "\\r\\n|")
			if len > 0 {
				regexString = regexString[:len]
				nsp.RegexString = strings.TrimSpace(regexString)
				if strings.Index(line, "p/") > 0 {
					product := strings.TrimSpace(line[strings.Index(line, "p/"):])[2:]
					if strings.Index(product, "/") > 0 {
						product = product[:strings.Index(product, "/")]
						nsp.ProbeProduct = product
					}
				}
				if nsp.Service != "" && nsp.RegexString != "" {
					NmapProbes.NSP = append(NmapProbes.NSP, nsp)
				}
			}
		}

	}
}

func isCommand(line string) bool {
	//删除注释行和空行
	if len(line) < 2 {
		return false
	}
	if line[:1] == "#" {
		return false
	}
	//删除异常命令
	commandName := line[:strings.Index(line, " ")]
	commandArr := []string{
		"match", "softmatch",
	}
	for _, item := range commandArr {
		if item == commandName {
			return true
		}
	}
	return false
}

func repairNMAPString(nmapServiceProbes string) string {
	nmapServiceProbes = strings.ReplaceAll(nmapServiceProbes, "${backquote}", "`")
	nmapServiceProbes = strings.ReplaceAll(nmapServiceProbes, `q|GET / HTTP/1.0\r\n\r\n|`,
		`q|GET / HTTP/1.0\r\nHost: {Host}\r\nUser-Agent: Mozilla/5.0 (Windows; U; MSIE 9.0; Windows NT 9.0; en-US)\r\nAccept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2\r\nAccept: */*\r\n\r\n|`)
	nmapServiceProbes = strings.ReplaceAll(nmapServiceProbes, `\1`, `$1`)
	nmapServiceProbes = strings.ReplaceAll(nmapServiceProbes, `(?=\\)`, `(?:\\)`)
	nmapServiceProbes = strings.ReplaceAll(nmapServiceProbes, `(?=[\w._-]{5,15}\r?\n$)`, `(?:[\w._-]{5,15}\r?\n$)`)
	nmapServiceProbes = strings.ReplaceAll(nmapServiceProbes, `(?:[^\r\n]*r\n(?!\r\n))*?`, `(?:[^\r\n]+\r\n)*?`)
	nmapServiceProbes = strings.ReplaceAll(nmapServiceProbes, `(?:[^\r\n]*\r\n(?!\r\n))*?`, `(?:[^\r\n]+\r\n)*?`)
	nmapServiceProbes = strings.ReplaceAll(nmapServiceProbes, `(?:[^\r\n]+\r\n(?!\r\n))*?`, `(?:[^\r\n]+\r\n)*?`)
	nmapServiceProbes = strings.ReplaceAll(nmapServiceProbes, `(?!2526)`, ``)
	nmapServiceProbes = strings.ReplaceAll(nmapServiceProbes, `(?!400)`, ``)
	nmapServiceProbes = strings.ReplaceAll(nmapServiceProbes, `(?!\0\0)`, ``)
	nmapServiceProbes = strings.ReplaceAll(nmapServiceProbes, `(?!/head>)`, ``)
	nmapServiceProbes = strings.ReplaceAll(nmapServiceProbes, `(?!HTTP|RTSP|SIP)`, ``)
	nmapServiceProbes = strings.ReplaceAll(nmapServiceProbes, `(?!.*[sS][sS][hH]).*`, `.*`)
	nmapServiceProbes = strings.ReplaceAll(nmapServiceProbes, `(?!\xff)`, `.`)
	nmapServiceProbes = strings.ReplaceAll(nmapServiceProbes, `(?!x)`, `[^x]`)
	nmapServiceProbes = strings.ReplaceAll(nmapServiceProbes, `(?<=.)`, `(?:.)`)
	nmapServiceProbes = strings.ReplaceAll(nmapServiceProbes, `(?<=\?)`, `(?:\?)`)
	nmapServiceProbes = strings.ReplaceAll(nmapServiceProbes, `\x20\x02\x00.`, `\x20\x02..`)
	nmapServiceProbes = strings.ReplaceAll(nmapServiceProbes, `match rtmp`, `# match rtmp`)
	nmapServiceProbes = strings.ReplaceAll(nmapServiceProbes, `nmap`, `pamn`)
	nmapServiceProbes = strings.ReplaceAll(nmapServiceProbes, `Nmap`, `pamn`)
	return nmapServiceProbes
}
