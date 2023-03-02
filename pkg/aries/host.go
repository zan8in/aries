package aries

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"os"
	"strings"

	"github.com/remeh/sizedwaitgroup"
	"github.com/zan8in/aries/pkg/util/fileutil"
	"github.com/zan8in/aries/pkg/util/iputil"
	"github.com/zan8in/gologger"
)

var (
	tempfile   = "aries-temp-hosts-*"
	ExcludeIps = []string{}
)

func (runner *Runner) PreprocessingHosts() error {
	var err error

	tempHosts, err := os.CreateTemp("", tempfile)
	if err != nil {
		return err
	}
	defer tempHosts.Close()

	ExcludeIps, _ = parseExcludedIps(runner.options)

	if len(runner.options.Host) > 0 {
		for _, v := range runner.options.Host {
			fmt.Fprintf(tempHosts, "%s\n", v)
		}
	}

	if len(runner.options.HostsFile) > 0 {
		f, err := os.Open(runner.options.HostsFile)
		if err != nil {
			return err
		}
		defer f.Close()

		if _, err := io.Copy(tempHosts, f); err != nil {
			return err
		}
	}

	runner.tempHostFile = tempHosts.Name()

	defer close(runner.hostChan)

	wg := sizedwaitgroup.New(runner.options.Threads)
	f, err := os.Open(runner.tempHostFile)
	if err != nil {
		return err
	}
	defer f.Close()

	s := bufio.NewScanner(f)
	for s.Scan() {
		wg.Add()
		func(target string) {
			defer wg.Done()
			if err := runner.addTarget(target); err != nil {
				gologger.Warning().Msgf("%s\n", err)
			}
		}(s.Text())
	}
	wg.Wait()

	return err
}

func (runner *Runner) addTarget(target string) error {
	var err error

	target = strings.TrimSpace(target)
	if len(target) == 0 {
		return nil
	}

	if isExcludeIp(target, ExcludeIps) {
		return fmt.Errorf("%s is Exclude Ip", target)
	}

	if iputil.IsCIDR(target) {
		runner.hostChan <- iputil.ToCidr(target)
		if err := runner.scanner.IPRanger.AddHostWithMetadata(target, "cidr"); err != nil { // Add cidr directly to ranger, as single ips would allocate more resources later
			gologger.Warning().Msgf("%s\n", err)
		}
		return nil
	}

	if iputil.IsIP(target) {
		ip := net.ParseIP(target)
		// convert ip4 expressed as ip6 back to ip4
		if ip.To4() != nil {
			target = ip.To4().String()
		}
		runner.hostChan <- iputil.ToCidr(target)

		err := runner.scanner.IPRanger.AddHostWithMetadata(target, "ip")
		if err != nil {
			gologger.Warning().Msgf("%s\n", err)
		}
		return nil
	}

	ips, err := runner.resolveFQDN(target)
	if err != nil {
		return err
	}
	for _, ip := range ips {
		if isExcludeIp(ip, ExcludeIps) {
			return fmt.Errorf("%s is Exclude Ip", ip)
		}

		runner.hostChan <- iputil.ToCidr(ip)
		if err := runner.scanner.IPRanger.AddHostWithMetadata(ip, target); err != nil {
			gologger.Warning().Msgf("%s\n", err)
		}
	}

	return err
}

func (r *Runner) resolveFQDN(target string) ([]string, error) {
	// ipsV4, ipsV6, err := r.host2ips(target)
	addrs, err := net.LookupHost(target)
	if err != nil {
		return []string{}, err
	}

	var (
		initialHosts []string
		hostIPS      []string
	)

	initialHosts = append(initialHosts, addrs...)

	if len(initialHosts) == 0 {
		return []string{}, nil
	}

	hostIPS = append(hostIPS, initialHosts[0])

	return hostIPS, nil
}

func parseExcludedIps(options *Options) ([]string, error) {
	var excludedIps []string
	if options.ExcludeIps != "" {
		excludedIps = append(excludedIps, strings.Split(options.ExcludeIps, ",")...)
	}

	if options.ExcludeIpsFile != "" {
		cdata, err := fileutil.ReadFile(options.ExcludeIpsFile)
		if err != nil {
			return excludedIps, err
		}
		for ip := range cdata {
			// if isIpOrCidr(ip) {
			excludedIps = append(excludedIps, ip)
			// }
		}
	}

	return excludedIps, nil
}

// func isIpOrCidr(s string) bool {
// 	return iputil.IsIP(s) || iputil.IsCIDR(s)
// }

func isExcludeIp(ip string, excludeIps []string) bool {
	if len(excludeIps) == 0 {
		return false
	}
	for _, eip := range excludeIps {
		if ip == eip {
			return true
		}
	}
	return false
}
