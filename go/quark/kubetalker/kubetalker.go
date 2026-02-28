package kubetalker

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"sync"
	"time"

	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/clientcmd"
)

type Handle struct {
	once        sync.Once
	stopCh      chan struct{}
	ctx         context.Context
	cancel      context.CancelFunc
	err         error
	outputMutex sync.Mutex
	output      *os.File
	addMsgLen   bool
	podFactory  informers.SharedInformerFactory
	nodeFactory informers.SharedInformerFactory
}

func (h *Handle) fetchClusterVersion(ctx context.Context, clientset *kubernetes.Clientset) error {
	version, err := clientset.Discovery().ServerVersion()
	if err != nil {
		return err
	}
	data := map[string]string{
		"kind":    "ClusterVersion",
		"version": version.String(),
	}
	h.forwardAny(data)

	return nil
}

func (h *Handle) fetchGCP(ctx context.Context) error {
	uri := url.URL{
		Scheme:   "http",
		Host:     "169.254.169.254",
		Path:     "/computeMetadata/v1",
		RawQuery: "recursive=true&alt=json",
	}

	req, err := http.NewRequestWithContext(ctx, "GET", uri.String(), nil)
	if err != nil {
		return err
	}
	req.Header.Add("Metadata-Flavor", "Google")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	if resp.StatusCode != 200 {
		return fmt.Errorf("HTTP GET error: %s", resp.Status)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	// Add kind
	var data map[string]interface{}
	err = json.Unmarshal(body, &data)
	if err != nil {
		return err
	}
	data["kind"] = "GcpMeta"
	h.forwardAny(data)

	return nil
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

func (h *Handle) Stop() {
	h.Fail(nil)
	h.Wait()
}

func (h *Handle) Fail(err error) {
	h.once.Do(func() {
		h.err = err
		h.cancel()
		close(h.stopCh)
	})
}

func (h *Handle) Wait() error {
	<-h.stopCh
	<-h.ctx.Done()
	// If we read h.stopCh, then Shutdown must terminate
	h.nodeFactory.Shutdown()
	h.podFactory.Shutdown()

	return h.err
}

func Start(addMsgLen bool, nodeName string, Kflag string, output *os.File) (*Handle, error) {
	var err error
	var config *rest.Config
	var h *Handle

	if nodeName == "" {
		nodeName = os.Getenv("QUARK_NODE_NAME")
	}
	if nodeName == "" {
		return nil, fmt.Errorf("can't fetch kubernetes node name")
	}

	config, err = fetchConfig(Kflag)
	if err != nil {
		return nil, err
	}

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, err
	}

	h = &Handle{}
	h.addMsgLen = addMsgLen
	h.output = output
	h.stopCh = make(chan struct{})
	h.ctx, h.cancel = context.WithTimeout(context.Background(), 5*time.Second)

	gotNode := false
	gotNodeChan := make(chan struct{})

	nodeOptions := func(options *metav1.ListOptions) {
		options.FieldSelector = "metadata.name=" + nodeName
	}
	h.nodeFactory = informers.NewSharedInformerFactoryWithOptions(clientset, 0,
		informers.WithTweakListOptions(nodeOptions))
	nodeInformer := h.nodeFactory.Core().V1().Nodes().Informer()
	nodeInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			node := obj.(*v1.Node)
			h.forwardNode(node)
			if !gotNode {
				gotNode = true
				gotNodeChan <- struct{}{}
			}
		},
		UpdateFunc: func(oldObj, newObj interface{}) {
			newNode := newObj.(*v1.Node)
			h.forwardNode(newNode)
		},
		DeleteFunc: func(obj interface{}) {
			node := obj.(*v1.Node)
			h.forwardNode(node)
		},
	})

	podOptions := func(options *metav1.ListOptions) {
		options.FieldSelector = "spec.nodeName=" + nodeName
	}
	h.podFactory = informers.NewSharedInformerFactoryWithOptions(clientset, 0,
		informers.WithTweakListOptions(podOptions))
	podInformer := h.podFactory.Core().V1().Pods().Informer()
	podInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			pod := obj.(*v1.Pod)
			// We don't care about addition without containerStatuses
			// No point in forwarding Pending, when it gets to Running it will have what we want
			if len(pod.Status.ContainerStatuses) == 0 ||
				pod.Status.Phase == v1.PodPending {
				return
			}
			h.forwardPod(pod)
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

			h.forwardPod(newPod)
		},
		DeleteFunc: func(obj interface{}) {
			if pod, ok := obj.(*v1.Pod); ok {
				h.forwardPod(pod)
			} else {
				tombstone, ok := obj.(cache.DeletedFinalStateUnknown)
				if !ok {
					fmt.Fprintf(os.Stderr, "Error decoding object when deleting pod, could not get object from tombstone: %#v\n", obj)
					return
				}
				if pod, ok := tombstone.Obj.(*v1.Pod); ok {
					h.forwardPod(pod)
				} else {
					fmt.Fprintf(os.Stderr, "Error decoding object when deleting pod, tombstone contained non-Pod object: %#v\n", tombstone.Obj)
				}
			}
		},
	})

	h.podFactory.Start(h.stopCh)
	h.nodeFactory.Start(h.stopCh)

	go h.fetchClusterVersion(h.ctx, clientset)
	go h.fetchGCP(h.ctx)

	// Wait for an Add(node) for up to 5 seconds
	go func() {
		tmo := time.NewTimer(5 * time.Second)
		defer tmo.Stop()

		select {
		case <-gotNodeChan:
		case <-tmo.C:
			h.Fail(fmt.Errorf("didn't receive node"))
		}
	}()

	return h, nil
}

func (h *Handle) forwardNode(node *v1.Node) {
	node.TypeMeta.Kind = "Node"
	h.forwardAny(node)
}

func (h *Handle) forwardPod(pod *v1.Pod) {
	pod.TypeMeta.Kind = "Pod"
	h.forwardAny(pod)
}

func (h *Handle) forwardAny(obj interface{}) {
	j, err := json.Marshal(obj)
	if err != nil {
		h.Fail(err)
		return
	}

	if h.addMsgLen {
		var buffer bytes.Buffer

		// Golang doesn't export a WriteV, so we have to stash it in a buffer :/
		err = binary.Write(&buffer, binary.NativeEndian, uint32(len(j)))
		if err != nil {
			h.Fail(err)
			return
		}
		_, err = buffer.Write(j)
		if err != nil {
			h.Fail(err)
			return
		}
		h.outputMutex.Lock()
		_, err = h.output.Write(buffer.Bytes())
		h.outputMutex.Unlock()
		if err != nil {
			h.Fail(err)
			return
		}
	} else {
		h.outputMutex.Lock()
		_, err = h.output.Write(j)
		h.outputMutex.Unlock()
		if err != nil {
			h.Fail(err)
			return
		}
	}
	// pretty, _ := json.MarshalIndent(obj, "", "  ")
	// fmt.Fprintf(os.Stderr, "%s\n", pretty)
}
