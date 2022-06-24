/*

acm-certificate-agent
Centre for Digital Transformation of Health
Copyright Kit Huckvale 2022.

*/

//lint:file-ignore ST1005 Override golang logging/error formatting conventions (use Validitron standard which is 'Sentence case with punctuation.')

package controllers

import (
	"context"
	"fmt"
	"strconv"

	cm "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	"github.com/pkg/errors"
	corev1 "k8s.io/api/core/v1"
	k8serr "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	"Validitron/k8s-acm-certificate-agent/global"
)

// CertificateReconciler allows certificate-agent to be enabled by annotating the cert-manager Certificate rather than the Secret itself.
// The only responsibility of CertificateReconciler is to add/remove management annotations from the Secret.
// Annotations are then picked up by SecretReconciler which does the actual work of communicating with ACM.
type CertificateReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

func (r *CertificateReconciler) SetupWithManager(mgr ctrl.Manager) error {
	// Tells the controller which object type this reconciler will handle.
	return ctrl.NewControllerManagedBy(mgr).
		For(&cm.Certificate{}).
		WithLogConstructor(buildLogConstructor(mgr, "certificate-reconciler", "cert-manager.io", "certificate")). // When multiple controllers running with a single manager, the log auto-constructor does not work. Therefore we must do manually.
		Complete(r)
}

func (r *CertificateReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {

	log := log.FromContext(ctx)
	finalizerID := global.DOMAIN_NAME + "/" + global.PACKAGE_NAME

	certificate := &cm.Certificate{}
	if err := r.Get(ctx, req.NamespacedName, certificate); err != nil {
		if !k8serr.IsNotFound(err) {
			log.Error(err, fmt.Sprintf("Unable to retrieve Certificate '%s'.", req.NamespacedName))
		}
		return ctrl.Result{RequeueAfter: defaultRequeueLatency}, client.IgnoreNotFound(err)
	}

	log.Info(fmt.Sprintf("Processing Certificate %s...", req.NamespacedName))

	// Certificate is marked for deletion, so clean up annotations (if they exist) on the Secret regardless of the management state.
	if !certificate.ObjectMeta.DeletionTimestamp.IsZero() {

		// Finalizer ensures object is retained until clean-up complete.
		if containsString(certificate.ObjectMeta.Finalizers, finalizerID) {

			// Secret may not yet exist, so fail silently if we can't get it.
			secret, err := r.GetSecret(certificate)
			if err == nil {

				log.Info(fmt.Sprintf("Stripping annotations from Certificate-managed Secret '%s'...", secret.Name))
				err := r.DeleteSecretManagementAnnotations(secret)
				if err != nil {
					// Log the problem but allow the certificate to be
					log.Error(err, "Unable to update Secret.")
					return ctrl.Result{}, err
				}

			}
		}

		// Remove our finalizer from the Certificate. First make sure we're using the most recent version of the Certificate object.
		if err := r.Get(ctx, req.NamespacedName, certificate); err != nil {
			if !k8serr.IsNotFound(err) {
				log.Error(err, fmt.Sprintf("Unable to retrieve Certificate '%s'.", req.NamespacedName))
			}
			return ctrl.Result{RequeueAfter: defaultRequeueLatency}, client.IgnoreNotFound(err)
		}

		certificate.ObjectMeta.Finalizers = removeString(certificate.ObjectMeta.Finalizers, finalizerID)
		if err := r.Update(ctx, certificate); err != nil {
			return ctrl.Result{RequeueAfter: defaultRequeueLatency}, errors.Wrap(err, "Could not remove finalizer from Certificate.")
		}

		log.Info("Certificate is marked for deletion: clean up complete.")
		return ctrl.Result{}, nil
	}

	// Register finalizer if it does not exist
	if !containsString(certificate.ObjectMeta.Finalizers, finalizerID) {
		certificate.ObjectMeta.Finalizers = append(certificate.ObjectMeta.Finalizers, finalizerID)
		if err := r.Update(ctx, certificate); err != nil {
			return ctrl.Result{RequeueAfter: defaultRequeueLatency}, errors.Wrap(err, "Could not add finalizer to Certificate.")
		}
	}

	// Retrieve linked Secret...
	secret, err := r.GetSecret(certificate)
	if err != nil {
		if k8serr.IsNotFound(err) {
			log.Info(fmt.Sprintf("Certificate-managed Secret '%s' not found: will retry.", certificate.Namespace+"/"+certificate.Spec.SecretName))
			return ctrl.Result{RequeueAfter: defaultRequeueLatency}, nil
		} else {
			log.Error(err, "Unable to retrieve Certificate-managed Secret.")
			return ctrl.Result{}, err
		}
	}

	// Verify that Secret can be managed...
	secretAgentEnabledAnnotation, secretAgentEnabled := secret.Annotations[global.AGENT_ENABLED_ANNOTATION]
	if secretAgentEnabled {
		secretAgentEnabled, _ = strconv.ParseBool(secretAgentEnabledAnnotation)
	}
	secretInheritsFrom, ok := secret.Annotations[global.AGENT_INHERITS_FROM_ANNOTATION]
	secretIsManagedByThisCertificate := false
	if secretAgentEnabled && (!ok || secretInheritsFrom == "") {
		log.Info(fmt.Sprintf("Secret '%s' is annotated to use certificate agent but not in managed mode: aborting.", namespacedName(secret.ObjectMeta)))
		return ctrl.Result{}, nil
	}
	if ok {
		if secretInheritsFrom == string(certificate.UID) {
			secretIsManagedByThisCertificate = true
		} else {
			log.Info(fmt.Sprintf("Secret '%s' is annotated as managed, but not by this Certificate: aborting.", namespacedName(secret.ObjectMeta)))
			return ctrl.Result{}, nil
		}
	}

	// At this point we:
	// 	 - Have a linked Secret, and
	//	 - Know that we can manage it (either because the Secret is explicitly marked as inheriting from this Certificate or it has no agent annotations)...

	// Detect if Certificate is annotated to enable ACM certificate management.
	certificateAgentEnabledAnnotation, certificateAgentEnabled := certificate.Annotations[global.AGENT_ENABLED_ANNOTATION]
	if certificateAgentEnabled {
		certificateAgentEnabled, _ = strconv.ParseBool(certificateAgentEnabledAnnotation)
	}

	// Certificate management is disabled or unspecified, so clean up annotations (if they exist) on the Secret.
	if !certificateAgentEnabled {
		log.Info(fmt.Sprintf("Certificate '%s' is not marked as managed.", req.NamespacedName))

		if secretIsManagedByThisCertificate {
			log.Info(fmt.Sprintf("Stripping annotations from Certificate-managed Secret '%s' (if present)...", namespacedName(secret.ObjectMeta)))
			err := r.DeleteSecretManagementAnnotations(secret)
			if err != nil {
				// Log the problem but allow the certificate to be
				log.Error(err, "Unable to update Secret.")
			}
		}

		return ctrl.Result{}, nil
	}

	// If the secret is marked as agent enabled and managed by this certificate...
	if secretAgentEnabled && secretIsManagedByThisCertificate {

		// Check to see if the secret as a certificateARN that we can cache (in case the secret is accidentally deleted.)
		secretCertificateArn, ok := secret.Annotations[global.AGENT_CERTIFICATE_ARN_ANNOTATION]
		if ok && secretCertificateArn != "" && certificate.Annotations[global.AGENT_CERTIFICATE_ARN_ANNOTATION] != secretCertificateArn {

			log.Info("Persisting ACM certificate ARN back to Certificate...")
			certificate.Annotations[global.AGENT_CERTIFICATE_ARN_ANNOTATION] = secretCertificateArn
			if err := r.Update(ctx, certificate); err != nil {
				return ctrl.Result{RequeueAfter: defaultRequeueLatency}, errors.Wrap(err, "Could not add annotation to Certificate.")
			}

		} else {
			// Otherwise, nothing to do.
			log.Info("Secret is configured for agent management: nothing to do.")
		}

		return ctrl.Result{}, nil
	}

	// Otherwise... mark Secret as agent-enabled.
	log.Info(fmt.Sprintf("Adding agent annotations to Certificate-managed Secret '%s'...", namespacedName(secret.ObjectMeta)))
	annotationErr := r.AddSecretManagementAnnotations(secret, certificate)
	if annotationErr != nil {
		log.Error(annotationErr, "Unable to update Secret.")
		return ctrl.Result{RequeueAfter: defaultRequeueLatency}, annotationErr
	}

	return ctrl.Result{}, nil
}

func (r *CertificateReconciler) GetSecret(certificate *cm.Certificate) (*corev1.Secret, error) {
	secretName := certificate.Spec.SecretName
	if secretName == "" {
		return nil, fmt.Errorf("Certificate '%s' does not have a secret name defined", certificate.Namespace+"/"+certificate.Name)
	}

	secret := &corev1.Secret{}
	err := r.Get(context.TODO(), types.NamespacedName{Name: secretName, Namespace: certificate.Namespace}, secret)
	if err != nil {
		return nil, err
	}

	return secret, nil
}

func (r *CertificateReconciler) DeleteSecretManagementAnnotations(secret *corev1.Secret) error {
	delete(secret.Annotations, global.AGENT_ENABLED_ANNOTATION)
	delete(secret.Annotations, global.AGENT_INHERITS_FROM_ANNOTATION)
	delete(secret.Annotations, global.AGENT_CERTIFICATE_ARN_ANNOTATION)
	delete(secret.Annotations, global.AGENT_CERTIFICATE_EXPIRY_DATE_ANNOTATION)
	delete(secret.Annotations, global.AGENT_CERTIFICATE_SERIAL_NUMBER_ANNOTATION)

	return r.Update(context.TODO(), secret, &client.UpdateOptions{})
}

func (r *CertificateReconciler) AddSecretManagementAnnotations(secret *corev1.Secret, certificate *cm.Certificate) error {
	secret.Annotations[global.AGENT_ENABLED_ANNOTATION] = "true"
	secret.Annotations[global.AGENT_INHERITS_FROM_ANNOTATION] = string(certificate.UID)

	// Propagate cached ARN to Secret (e.g. in case Secret was manually deleted in order to trigger a cert-manager reissue...)
	certificateArn, ok := certificate.Annotations[global.AGENT_CERTIFICATE_ARN_ANNOTATION]
	if ok && certificateArn != "" {
		secret.Annotations[global.AGENT_CERTIFICATE_ARN_ANNOTATION] = certificateArn
	}

	return r.Update(context.TODO(), secret, &client.UpdateOptions{})
}
