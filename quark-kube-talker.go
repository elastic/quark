package main

import (
	"fmt"
	"os"
	"strconv"
	"syscall"
	"encoding/json"
	"encoding/binary"
	"bytes"
	//	"path/filepath"

	v1 "k8s.io/api/core/v1"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
	//	"k8s.io/client-go/util/homedir"
	"k8s.io/client-go/tools/cache"
)

func main() {
	if len(os.Args) != 3 {
		panic("bad args")
	}

	configPath := os.Args[1]
	fd, err := strconv.Atoi(os.Args[2])
	err = syscall.SetNonblock(fd, true)
	if err != nil {
		panic("can't set non block")
	}
	file := os.NewFile(uintptr(fd), "")

	fmt.Printf("starting: %+v (fd=%+v) (file=%+v)", os.Args, fd, file)

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
			fmt.Printf("POD ADDED: %s/%s\n", pod.Namespace, pod.Name)
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

			fmt.Printf("POD UPDATED: %s/%s (Status: %s -> %s)\n", newPod.Namespace, newPod.Name, oldPod.Status.Phase, newPod.Status.Phase)
			forward(file, newPod)
		},
		DeleteFunc: func(obj interface{}) {
			// Kubernetes client-go sends a FinalStateUnknown object for deleted items
			// if the object was not in the local cache.
			if pod, ok := obj.(*v1.Pod); ok {
				fmt.Printf("POD DELETED: %s/%s\n", pod.Namespace, pod.Name)
				forward(file, pod)
			} else {
				tombstone, ok := obj.(cache.DeletedFinalStateUnknown)
				if !ok {
					fmt.Fprintf(os.Stderr, "Error decoding object when deleting pod, could not get object from tombstone: %#v\n", obj)
					return
				}
				if pod, ok := tombstone.Obj.(*v1.Pod); ok {
					fmt.Printf("POD DELETED (from tombstone): %s/%s\n", pod.Namespace, pod.Name)
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

	fmt.Println("All done")
}

func forward(f *os.File, pod *v1.Pod) {
	// Golang doesn't export a WriteV, so we have to stash it in a buffer :/
	var buffer bytes.Buffer

	j, err := json.Marshal(pod)
	if err != nil {
		panic(err.Error())
	}

	err = binary.Write(&buffer, binary.LittleEndian, uint32(len(j)))
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
	// pretty, _ := json.MarshalIndent(obj, "", "  ")
	// fmt.Printf("%s\n", pretty)
}
