package controller

import (
	"fmt"
	"time"

	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"
)

// NetworkPolicyInformer handles the watching of NetworkPolicy resources
type NetworkPolicyInformer struct {
	informer cache.SharedIndexInformer
	queue    workqueue.RateLimitingInterface
	handler  PolicyEventHandler
}

// PolicyEventHandler defines the interface for handling policy events
type PolicyEventHandler interface {
	OnAdd(policy *networkingv1.NetworkPolicy)
	OnUpdate(oldPolicy, newPolicy *networkingv1.NetworkPolicy)
	OnDelete(policy *networkingv1.NetworkPolicy)
}

// NewNetworkPolicyInformer creates a new NetworkPolicy informer
func NewNetworkPolicyInformer(clientset *kubernetes.Clientset, handler PolicyEventHandler) *NetworkPolicyInformer {
	factory := informers.NewSharedInformerFactory(clientset, time.Minute*10)
	informer := factory.Networking().V1().NetworkPolicies().Informer()
	queue := workqueue.NewRateLimitingQueue(workqueue.DefaultControllerRateLimiter())

	npInformer := &NetworkPolicyInformer{
		informer: informer,
		queue:    queue,
		handler:  handler,
	}

	informer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			key, err := cache.MetaNamespaceKeyFunc(obj)
			if err == nil {
				queue.Add(key)
			}
		},
		UpdateFunc: func(old, new interface{}) {
			key, err := cache.MetaNamespaceKeyFunc(new)
			if err == nil {
				queue.Add(key)
			}
		},
		DeleteFunc: func(obj interface{}) {
			key, err := cache.DeletionHandlingMetaNamespaceKeyFunc(obj)
			if err == nil {
				queue.Add(key)
			}
		},
	})

	return npInformer
}

// Run starts the informer
func (i *NetworkPolicyInformer) Run(stopCh <-chan struct{}) {
	defer runtime.HandleCrash()
	defer i.queue.ShutDown()

	go i.informer.Run(stopCh)

	if !cache.WaitForCacheSync(stopCh, i.informer.HasSynced) {
		runtime.HandleError(fmt.Errorf("timed out waiting for caches to sync"))
		return
	}

	wait.Until(i.runWorker, time.Second, stopCh)
}

func (i *NetworkPolicyInformer) runWorker() {
	for i.processNextItem() {
	}
}

func (i *NetworkPolicyInformer) processNextItem() bool {
	key, quit := i.queue.Get()
	if quit {
		return false
	}
	defer i.queue.Done(key)

	obj, exists, err := i.informer.GetIndexer().GetByKey(key.(string))
	if err != nil {
		runtime.HandleError(fmt.Errorf("error processing item %v: %v", key, err))
		return true
	}

	if !exists {
		// Handle deletion
		if policy, ok := obj.(*networkingv1.NetworkPolicy); ok {
			i.handler.OnDelete(policy)
		}
		return true
	}

	policy, ok := obj.(*networkingv1.NetworkPolicy)
	if !ok {
		runtime.HandleError(fmt.Errorf("invalid object type: %T", obj))
		return true
	}

	// Handle add/update
	i.handler.OnUpdate(nil, policy)
	return true
} 