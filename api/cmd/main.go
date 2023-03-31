package main

import (
	"fmt"

	"github.com/zan8in/aries/api"
)

func main() {

	rst, err := api.PortScanner("hackerone.com", "", 1000)
	if err != nil {
		fmt.Println(err.Error())
		return
	}

	for _, r := range rst {
		fmt.Println(r)
	}

}
