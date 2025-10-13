package main

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"os"
	"time"

	getopt "github.com/pborman/getopt/v2"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/clientcmd"
)

func fatal(v any) {
	fmt.Fprintf(os.Stderr, "quark-kube-talker: fatal: %v\n", v)
	os.Exit(1)
}

func fetchConfig(Kflag string) (*rest.Config, error) {
	var configPath string

	// Try only ENV
	if Kflag == "ENV" {
		return rest.InClusterConfig()
	}

	// Try ENV first, fallback to config path otherwise
	if Kflag == "" {
		config, err := rest.InClusterConfig()
		if err == nil {
			return config, nil
		}
		// config, err := clientcmd.BuildConfigFromFlags("", configPath)
		// rest.InClusterConfig()
		if configPath, err = os.UserHomeDir(); err != nil {
			return nil, err
		}
		configPath += "/.kube/config"

		config, err = clientcmd.BuildConfigFromFlags("", configPath)
		return config, err
	}

	// Treat Kflag as configPath
	configPath = Kflag
	return clientcmd.BuildConfigFromFlags("", configPath)
}

func main() {
	var err error
	var addMsgLen bool
	var Kflag string
	var helpFlag bool
	var nodeName string
	var config *rest.Config

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

	if nodeName == "" {
		nodeName = os.Getenv("QUARK_NODE_NAME")
	}
	if nodeName == "" {
		fatal("can't fetch kubernetes node name")
	}

	config, err = fetchConfig(Kflag)
	if err != nil {
		fatal(err)
	}

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		fatal(err)
	}

	gotNode := false
	gotNodeChan := make(chan struct{})

	nodeOptions := func(options *metav1.ListOptions) {
		options.FieldSelector = "metadata.name=" + nodeName
	}
	nodeFactory := informers.NewSharedInformerFactoryWithOptions(clientset, 0,
		informers.WithTweakListOptions(nodeOptions))
	nodeInformer := nodeFactory.Core().V1().Nodes().Informer()
	nodeInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			node := obj.(*v1.Node)
			forwardNode(node, addMsgLen)
			if !gotNode {
				gotNode = true
				gotNodeChan <- struct{}{}
			}
		},
		UpdateFunc: func(oldObj, newObj interface{}) {
			newNode := newObj.(*v1.Node)
			forwardNode(newNode, addMsgLen)
		},
		DeleteFunc: func(obj interface{}) {
			node := obj.(*v1.Node)
			forwardNode(node, addMsgLen)
		},
	})

	podOptions := func(options *metav1.ListOptions) {
		options.FieldSelector = "spec.nodeName=" + nodeName
	}
	podFactory := informers.NewSharedInformerFactoryWithOptions(clientset, 0,
		informers.WithTweakListOptions(podOptions))
	podInformer := podFactory.Core().V1().Pods().Informer()
	podInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			pod := obj.(*v1.Pod)
			// We don't care about addition without containerStatuses
			// No point in forwarding Pending, when it gets to Running it will have what we want
			if len(pod.Status.ContainerStatuses) == 0 ||
				pod.Status.Phase == v1.PodPending {
				return
			}
			forwardPod(pod, addMsgLen)
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

			forwardPod(newPod, addMsgLen)
		},
		DeleteFunc: func(obj interface{}) {
			if pod, ok := obj.(*v1.Pod); ok {
				forwardPod(pod, addMsgLen)
			} else {
				tombstone, ok := obj.(cache.DeletedFinalStateUnknown)
				if !ok {
					fmt.Fprintf(os.Stderr, "Error decoding object when deleting pod, could not get object from tombstone: %#v\n", obj)
					return
				}
				if pod, ok := tombstone.Obj.(*v1.Pod); ok {
					forwardPod(pod, addMsgLen)
				} else {
					fmt.Fprintf(os.Stderr, "Error decoding object when deleting pod, tombstone contained non-Pod object: %#v\n", tombstone.Obj)
				}
			}
		},
	})

	stopCh := make(chan struct{})
	defer close(stopCh)

	podFactory.Start(stopCh)
	nodeFactory.Start(stopCh)

	// Wait for an Add(node) for up to 5 seconds
	go func() {
		select {
		case <-gotNodeChan:
		case <-time.After(5 * time.Second):
			fatal("didn't receive node")
		}
	}()

	<-stopCh
}

func forwardNode(node *v1.Node, addMsgLen bool) {
	node.TypeMeta.Kind = "Node"
	forwardAny(node, addMsgLen)
}

func forwardPod(pod *v1.Pod, addMsgLen bool) {
	pod.TypeMeta.Kind = "Pod"
	forwardAny(pod, addMsgLen)
}

func forwardAny(obj interface{}, addMsgLen bool) {
	j, err := json.Marshal(obj)
	if err != nil {
		fatal(err)
	}

	if addMsgLen {
		var buffer bytes.Buffer

		// Golang doesn't export a WriteV, so we have to stash it in a buffer :/
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
		_, err = os.Stdout.Write(j)
		if err != nil {
			fatal(err)
		}
	}
	// pretty, _ := json.MarshalIndent(obj, "", "  ")
	// fmt.Fprintf(os.Stderr, "%s\n", pretty)
}
