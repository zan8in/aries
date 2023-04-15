package main

import (
	"fmt"
	"sync"

	"github.com/zan8in/aries/api"
)

func main() {

	wg := sync.WaitGroup{}
	wg.Add(1)
	api.OnResult = func(r api.Result) {
		if r.Status == api.Done {
			wg.Done()
		} else {
			fmt.Printf("!!Discovered open port %d on (%s) %s service:%s, product:%s\n", r.Port, r.Host, r.IP, r.Service, r.Product)
		}
	}

	rst, err := api.PortScanner([]string{"example.com"}, "", 0)
	if err != nil {
		fmt.Println(err.Error())
		return
	}

	for _, r := range rst {
		fmt.Println(r)
	}
	wg.Wait()
	fmt.Println(".........", len(rst))

}
