/*

acm-certificate-agent
Centre for Digital Transformation of Health
Copyright Kit Huckvale 2022.

*/

//lint:file-ignore ST1005 Override golang logging/error formatting conventions (use Validitron standard instead.)

package controllers

import (
	"context"

	networking "k8s.io/api/networking/v1"
	k8serr "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
)

// SecretReconciler reconciles cert-manager Certificate objects.
type IngressReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

func (r *IngressReconciler) SetupWithManager(mgr ctrl.Manager) error {
	// Tells the controller which object type this reconciler will handle.
	return ctrl.NewControllerManagedBy(mgr).
		For(&networking.Ingress{}).
		Complete(r)
}

func (r *IngressReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {

	log := log.FromContext(ctx)

	ingress := &networking.Ingress{}
	if err := r.Client.Get(ctx, req.NamespacedName, ingress); err != nil {
		if !k8serr.IsNotFound(err) {
			log.Error(err, "Unable to retrieve Secret.")
		}
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	log.Info("Wah")

	return ctrl.Result{}, nil
}
