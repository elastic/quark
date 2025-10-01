package main

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"syscall"

	v1 "k8s.io/api/core/v1"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/clientcmd"
)

func main() {
	if len(os.Args) != 3 {
		panic("usage: quark-kube-talker kube_config_path fd_number")
	}

	configPath := os.Args[1]
	fd, err := strconv.Atoi(os.Args[2])
	if err != nil {
		panic(err.Error())
	}
	err = syscall.SetNonblock(fd, true)
	if err != nil {
		panic("can't set non block")
	}
	file := os.NewFile(uintptr(fd), "")

	config, err := clientcmd.BuildConfigFromFlags("", configPath)
	if err != nil {
		panic(err.Error())
	}

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		panic(err.Error())
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
			forward(file, pod)
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

			forward(file, newPod)
		},
		DeleteFunc: func(obj interface{}) {
			if pod, ok := obj.(*v1.Pod); ok {
				forward(file, pod)
			} else {
				tombstone, ok := obj.(cache.DeletedFinalStateUnknown)
				if !ok {
					fmt.Fprintf(os.Stderr, "Error decoding object when deleting pod, could not get object from tombstone: %#v\n", obj)
					return
				}
				if pod, ok := tombstone.Obj.(*v1.Pod); ok {
					forward(file, pod)
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

func forward(f *os.File, pod *v1.Pod) {
	// Golang doesn't export a WriteV, so we have to stash it in a buffer :/
	var buffer bytes.Buffer

	j, err := json.Marshal(pod)
	if err != nil {
		panic(err.Error())
	}

	err = binary.Write(&buffer, binary.NativeEndian, uint32(len(j)))
	if err != nil {
		panic(err.Error())
	}
	_, err = buffer.Write(j)
	if err != nil {
		panic(err.Error())
	}
	_, err = f.Write(buffer.Bytes())
	if err != nil {
		panic(err.Error())
	}
	// pretty, _ := json.MarshalIndent(pod, "", "  ")
	// fmt.Fprintf(os.Stderr, "%s\n", pretty)
}
