package main

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"os"

	getopt "github.com/pborman/getopt/v2"
	v1 "k8s.io/api/core/v1"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/clientcmd"
)

var (
	addMsgLen  bool
	helpFlag   bool
	configPath string
)

func fatal(v any) {
	fmt.Fprintf(os.Stderr, "quark-kube-talker: fatal: %v\n", v)
	os.Exit(1)
}

func main() {
	var err error

	getopt.Flag(&helpFlag, 'h', "print this help")
	getopt.Flag(&addMsgLen, 'm', "prefix messages with binary length")
	getopt.Flag(&configPath, 'K', "kubeconfig path")
	getopt.SetParameters("")
	getopt.Parse()

	if helpFlag || len(getopt.Args()) != 0 {
		getopt.Usage()
		os.Exit(1)
	}

	if configPath == "" {
		if configPath, err = os.UserHomeDir(); err != nil {
			fatal(err)
		}
		configPath += "/.kube/config"
	}

	config, err := clientcmd.BuildConfigFromFlags("", configPath)
	if err != nil {
		fatal(err)
	}

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		fatal(err)
	}

	factory := informers.NewSharedInformerFactory(clientset, 0)
	podInformer := factory.Core().V1().Pods().Informer()

	podInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			pod := obj.(*v1.Pod)
			// We don't care about addition without containerStatuses
			// No point in forwarding Pending, when it gets to Running it will have what we want
			if len(pod.Status.ContainerStatuses) == 0 ||
				pod.Status.Phase == v1.PodPending {
				return
			}
			forward(pod)
		},
		UpdateFunc: func(oldObj, newObj interface{}) {
			oldPod := oldObj.(*v1.Pod)
			newPod := newObj.(*v1.Pod)
			if oldPod.ResourceVersion == newPod.ResourceVersion {
				// Periodic resync will send update events for the same object.
				// We don't want to process these.
				return
			}
			// We don't care about updates without containerStatuses
			if len(newPod.Status.ContainerStatuses) == 0 ||
				newPod.Status.Phase == v1.PodPending {
				return
			}

			forward(newPod)
		},
		DeleteFunc: func(obj interface{}) {
			if pod, ok := obj.(*v1.Pod); ok {
				forward(pod)
			} else {
				tombstone, ok := obj.(cache.DeletedFinalStateUnknown)
				if !ok {
					fmt.Fprintf(os.Stderr, "Error decoding object when deleting pod, could not get object from tombstone: %#v\n", obj)
					return
				}
				if pod, ok := tombstone.Obj.(*v1.Pod); ok {
					forward(pod)
				} else {
					fmt.Fprintf(os.Stderr, "Error decoding object when deleting pod, tombstone contained non-Pod object: %#v\n", tombstone.Obj)
				}
			}
		},
	})

	stopCh := make(chan struct{})
	defer close(stopCh)

	factory.Start(stopCh)

	<-stopCh
}

func forward(pod *v1.Pod) {
	// Golang doesn't export a WriteV, so we have to stash it in a buffer :/

	j, err := json.Marshal(pod)
	if err != nil {
		fatal(err)
	}

	if addMsgLen {
		var buffer bytes.Buffer

		err = binary.Write(&buffer, binary.NativeEndian, uint32(len(j)))
		if err != nil {
			fatal(err)
		}
		_, err = buffer.Write(j)
		if err != nil {
			fatal(err)
		}
		_, err = os.Stdout.Write(buffer.Bytes())
		if err != nil {
			fatal(err)
		}
	} else {
		os.Stdout.Write(j)
	}
	// pretty, _ := json.MarshalIndent(pod, "", "  ")
	// fmt.Fprintf(os.Stderr, "%s\n", pretty)
}
