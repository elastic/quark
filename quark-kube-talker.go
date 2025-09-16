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
	nodeInformer := factory.Core().V1().Nodes().Informer()

	podInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			pod := obj.(*v1.Pod)
			// We don't care about addition without containerStatuses
			// No point in forwarding Pending, when it gets to Running it will have what we want
			if len(pod.Status.ContainerStatuses) == 0 ||
				pod.Status.Phase == v1.PodPending {
				return
			}
			forwardPod(file, pod)
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

			forwardPod(file, newPod)
		},
		DeleteFunc: func(obj interface{}) {
			if pod, ok := obj.(*v1.Pod); ok {
				forwardPod(file, pod)
			} else {
				tombstone, ok := obj.(cache.DeletedFinalStateUnknown)
				if !ok {
					fmt.Fprintf(os.Stderr, "Error decoding object when deleting pod, could not get object from tombstone: %#v\n", obj)
					return
				}
				if pod, ok := tombstone.Obj.(*v1.Pod); ok {
					forwardPod(file, pod)
				} else {
					fmt.Fprintf(os.Stderr, "Error decoding object when deleting pod, tombstone contained non-Pod object: %#v\n", tombstone.Obj)
				}
			}
		},
	})

	nodeInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			node := obj.(*v1.Node)
			forwardNode(file, node)
		},
		UpdateFunc: func(oldObj, newObj interface{}) {
			oldNode := oldObj.(*v1.Node)
			newNode := newObj.(*v1.Node)
			if oldNode.ResourceVersion == newNode.ResourceVersion {
				return
			}
			forwardNode(file, newNode)
		},
		DeleteFunc: func(obj interface{}) {
			if node, ok := obj.(*v1.Node); ok {
				forwardNode(file, node)
			} else {
				tombstone, ok := obj.(cache.DeletedFinalStateUnknown)
				if !ok {
					fmt.Fprintf(os.Stderr, "Error decoding object when deleting node, could not get object from tombstone: %#v\n", obj)
					return
				}
				if node, ok := tombstone.Obj.(*v1.Node); ok {
					forwardNode(file, node)
				} else {
					fmt.Fprintf(os.Stderr, "Error decoding object when deleting node, tombstone contained non-Node object: %#v\n", tombstone.Obj)
				}
			}
		},
	})

	stopCh := make(chan struct{})
	defer close(stopCh)

	factory.Start(stopCh)

	if version, err := clientset.Discovery().ServerVersion(); err == nil {
		forwardClusterVersion(file, version.GitVersion)
	}

	<-stopCh
}

func forwardPod(f *os.File, pod *v1.Pod) {
	// Golang doesn't export a WriteV, so we have to stash it in a buffer :/
	if pod == nil {
		return
	}
	pod.TypeMeta.Kind = "Pod"
	forward(f, pod)
}

func forwardNode(f *os.File, node *v1.Node) {
	if node == nil {
		return
	}
	node.TypeMeta.Kind = "Node"
	forward(f, node)
}

func forwardClusterVersion(f *os.File, version string) {
	payload := map[string]string{
		"kind":    "QuarkClusterVersion",
		"version": version,
	}
	forward(f, payload)
}

func forward(f *os.File, obj interface{}) {
	// Golang doesn't export a WriteV, so we have to stash it in a buffer :/
	var buffer bytes.Buffer

	j, err := json.Marshal(obj)
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
	// pretty, _ := json.MarshalIndent(obj, "", "  ")
	// fmt.Printf("%s\n", pretty)
}
