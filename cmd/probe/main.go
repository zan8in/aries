package main

import (
	"fmt"
	"strconv"
)

func main() {
	// probeservice.Test()
	// a := "32750 - 32810"
	str := ""
	for i := 55000; i <= 55003; i++ {
		str += strconv.Itoa(i) + ","
	}
	fmt.Println(str)
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
