// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 Elastic NV

package main

import (
	"fmt"

	quark "github.com/elastic/quark/go"
)

func main() {
	queue, err := quark.OpenQueue(quark.DefaultQueueAttr(), 64)
	if err != nil {
		panic(err)
	}
	defer queue.Close()

	pid1, ok := queue.Lookup(1)
	if ok {
		fmt.Printf("Yey for pid1\n %#v", pid1)
	}

	for {
		qevs, err := queue.GetEvents()
		if err != nil {
			panic(err)
		}
		for _, qev := range qevs {
			fmt.Printf("%#v", qev)
			if qev.Proc.Valid {
				fmt.Printf(" %#v", qev.Proc)
			}
			fmt.Printf("\n")
		}
		if len(qevs) == 0 {
			err = queue.Block()
			if err != nil {
				panic(err)
			}
		}
	}

}
