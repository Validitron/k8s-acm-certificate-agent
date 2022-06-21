/*

acm-certificate-agent
Centre for Digital Transformation of Health
Copyright Kit Huckvale 2022.

*/

//lint:file-ignore ST1005 Override golang logging/error formatting conventions (use Validitron standard instead.)

package controllers

import (
	"context"

	cm "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	k8serr "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
)

// SecretReconciler reconciles cert-manager Certificate objects.
type CertificateReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

func (r *CertificateReconciler) SetupWithManager(mgr ctrl.Manager) error {
	// Tells the controller which object type this reconciler will handle.
	return ctrl.NewControllerManagedBy(mgr).
		For(&cm.Certificate{}).
		Complete(r)
}

func (r *CertificateReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {

	log := log.FromContext(ctx)

	certificate := &cm.Certificate{}
	if err := r.Client.Get(ctx, req.NamespacedName, certificate); err != nil {
		if !k8serr.IsNotFound(err) {
			log.Error(err, "Unable to retrieve Secret.")
		}
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	return ctrl.Result{}, nil
}
