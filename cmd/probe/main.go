package main

import "github.com/zan8in/aries/pkg/probeservice"

func main() {
	probeservice.Test()
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
