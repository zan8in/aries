package main

import (
	"fmt"

	"github.com/zan8in/aries/api"
)

func main() {

	api.OnResult = func(r api.Result) {
		fmt.Printf("Discovered open port %d on (%s) %s service:%s, product:%s\n", r.Port, r.Host, r.IP, r.Service, r.Product)
	}

	rst, err := api.PortScanner([]string{"example.com", "lankegp.com", "hackerone.com"}, "", 0)
	if err != nil {
		fmt.Println(err.Error())
		return
	}

	for _, r := range rst {
		fmt.Println(r)
	}

}
