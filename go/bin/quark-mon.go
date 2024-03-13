package main

import (
	"fmt"
	"github.com/elastic/quark/go"
)

func main() {
	err := quark.QuarkInit()
	if err != nil {
		panic(err)
	}
	qq, err := quark.QuarkQueueOpen(64)
	if err != nil {
		panic(err)
	}
	for {
		qevs, err := qq.GetEvents()
		if err != nil {
			panic(err)
		}
		for _, qev := range qevs {
			fmt.Printf("%#v", qev)
			if qev.Proc != nil {
				fmt.Printf(" %#v", qev.Proc)
			}
			fmt.Printf("\n")
		}
		if len(qevs) == 0 {
			qq.Block()
		}
	}
	qq.Close()
	quark.QuarkClose()
}
