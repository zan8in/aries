package main

import (
	"fmt"
	"time"

	"github.com/zan8in/aries/pkg/probeservice/vscan"
)

func main() {
	v := vscan.VScan{}
	v.Init()

	var (
		config *vscan.Config
		target vscan.Target
	)
	config = &vscan.Config{}
	config.Rarity = 7
	config.SendTimeout = time.Duration(5) * time.Second
	config.ReadTimeout = time.Duration(5) * time.Second
	config.UseAllProbes = false
	config.NULLProbeOnly = false

	target = vscan.Target{}
	target.IP = "104.16.100.52"
	target.Port = 8443
	target.Protocol = "tcp"

	result, _ := v.Explore(target, config)
	fmt.Println(
		target.IP,
		target.Port,
		result,
	)
	// probeservice.Test()
	// a := "32750 - 32810"
	// str := ""
	// for i := 55000; i <= 55003; i++ {
	// 	str += strconv.Itoa(i) + ","
	// }
	// fmt.Println(str)
	// s, ok := probeservice.Probe.NmapServiceMap.Load(1)
	// if !ok {
	// 	fmt.Println("err")
	// 	return
	// }
	// fmt.Println(s)

	// probeservice.Probe.NmapServiceMap.Range(func(key, value interface{}) bool {
	// 	port := key.(int)
	// 	name := value.(string)
	// 	fmt.Println(port, name)
	// 	return true
	// })
}
