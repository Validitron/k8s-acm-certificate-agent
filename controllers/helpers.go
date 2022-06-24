package controllers

import (
	"strings"
	"time"

	"github.com/go-logr/logr"
	"k8s.io/klog/v2"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

// Internal helper methods should be camelCased.

const (
	defaultRequeueLatency = 20 * time.Second
)

// Helper functions to check and remove string from a slice of strings.
func containsString(slice []string, target string) bool {
	for _, item := range slice {
		if item == target {
			return true
		}
	}
	return false
}

func containsStringIgnoringCase(slice []string, target string) bool {
	for _, item := range slice {
		if strings.EqualFold(item, target) {
			return true
		}
	}
	return false
}

func removeString(slice []string, target string) (result []string) {
	for _, item := range slice {
		if item == target {
			continue
		}
		result = append(result, item)
	}
	return
}

func trimSpaceFromSliceElements(slice []string) (result []string) {
	for _, item := range slice {
		result = append(result, strings.TrimSpace(item))
	}
	return
}

func buildLogConstructor(mgr ctrl.Manager, controllerName string, controllerGroup string, controllerKind string) func(req *reconcile.Request) logr.Logger {

	// Adapted from https://github.com/kubernetes-sigs/controller-runtime/blob/c066edcfdcaeb6503e0c50cb7ed7fa82db15f130/pkg/builder/controller.go

	log := mgr.GetLogger()

	lowerCamelCaseKind := strings.ToLower(controllerKind[:1]) + controllerKind[1:]

	return func(req *reconcile.Request) logr.Logger {
		log := log
		if req != nil {
			log = log.WithValues(
				"controller", controllerName,
				"namespace", req.Namespace, "name", req.Name,
				"controllerGroup", controllerGroup,
				"controllerKind", controllerKind,
				lowerCamelCaseKind, klog.KRef(req.Namespace, req.Name),
			)
		}
		return log
	}

}

func namespacedName(meta ctrl.ObjectMeta) string {
	return meta.Namespace + "/" + meta.Name
}
