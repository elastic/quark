package main

import (
	"fmt"
	"os"
	"os/signal"

	getopt "github.com/pborman/getopt/v2"

	kubetalker "quark/quark/kubetalker"
)

func main() {
	var err error
	var addMsgLen bool
	var Kflag string
	var helpFlag bool
	var nodeName string
	var handle *kubetalker.Handle

	getopt.Flag(&helpFlag, 'h', "print this help")
	getopt.Flag(&addMsgLen, 'm', "prefix messages with binary length")
	getopt.Flag(&nodeName, 'n', "kubernetes node name")
	getopt.Flag(&Kflag, 'K', "kubeconfig path")
	getopt.SetParameters("")
	getopt.Parse()

	if helpFlag || len(getopt.Args()) != 0 {
		getopt.Usage()
		os.Exit(1)
	}

	handle, err = kubetalker.Start(addMsgLen, nodeName, Kflag, os.Stdout)
	if err != nil {
		fmt.Fprintf(os.Stderr, "quark-kube-talker: fatal: %v\n", err)
		os.Exit(1)
	}
	go func() {
		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, os.Interrupt)
		<-sigChan
		handle.Stop()
	}()
	err = handle.Wait()
	if err != nil {
		fmt.Fprintf(os.Stderr, "quark-kube-talker: fatal: %v\n", err)
		os.Exit(1)
	}
}
