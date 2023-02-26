package aries

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"os"
	"strings"

	"github.com/remeh/sizedwaitgroup"
	"github.com/zan8in/aries/pkg/util/iputil"
	"github.com/zan8in/gologger"
)

var tempfile = "aries-temp-hosts-*"

func (runner *Runner) PreprocessingHosts() error {
	var err error

	tempHosts, err := os.CreateTemp("", tempfile)
	if err != nil {
		return err
	}
	defer tempHosts.Close()

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
