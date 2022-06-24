/*

acm-certificate-agent
Centre for Digital Transformation of Health
Copyright Kit Huckvale 2022.

*/

//lint:file-ignore ST1005 Override golang logging/error formatting conventions (use Validitron standard which is 'Sentence case with punctuation.')

package controllers

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	networking "k8s.io/api/networking/v1"
	k8serr "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	"Validitron/k8s-acm-certificate-agent/global"
)

// IngressReconciler injects ACM certificate annotations into ALB-enabled Ingress objects by finding a matching SSL-containing Secret.
type IngressReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

func (r *IngressReconciler) SetupWithManager(mgr ctrl.Manager) error {

	// Index the type field on Secrets so we can filter these efficiently.
	if err := mgr.GetFieldIndexer().IndexField(context.Background(), &corev1.Secret{}, "type", func(rawObj client.Object) []string {
		secret := rawObj.(*corev1.Secret)
		if secret.Type == "" {
			return nil
		}
		return []string{string(secret.Type)}
	}); err != nil {
		return err
	}

	// Tells the controller which object type this reconciler will handle.
	return ctrl.NewControllerManagedBy(mgr).
		For(&networking.Ingress{}).
		WithLogConstructor(buildLogConstructor(mgr, "ingress-reconciler", "networking.k8s.io", "ingress")). // When multiple controllers running with a single manager, the log auto-constructor does not work. Therefore we must do manually.
		Complete(r)
}

func (r *IngressReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {

	log := log.FromContext(ctx)

	ingress := &networking.Ingress{}
	if err := r.Get(ctx, req.NamespacedName, ingress); err != nil {
		if !k8serr.IsNotFound(err) {
			log.Error(err, "Unable to retrieve Ingress.")
		}
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	log.Info(fmt.Sprintf("Processing Ingress %s...", req.NamespacedName))

	// Object is marked for deletion - nothing to do (the operator never removes synced ACM certificates.)
	if !ingress.ObjectMeta.DeletionTimestamp.IsZero() {
		log.Info("Ingress is marked for deletion: nothing to do.")
		return ctrl.Result{}, nil
	}

	// Detect if Ingress is annotated to enable ACM certificate management.
	certificateAgentEnabledAnnotation, certificateAgentEnabled := ingress.Annotations[global.AGENT_ENABLED_ANNOTATION]
	if certificateAgentEnabled {
		certificateAgentEnabled, _ = strconv.ParseBool(certificateAgentEnabledAnnotation)
	}

	if !certificateAgentEnabled {
		log.Info(fmt.Sprintf("Ingress '%s' is not marked as managed.", req.NamespacedName))
		return ctrl.Result{}, nil
	}

	// Make sure ingress is using ALB.
	ingressClass, ok := ingress.Annotations[global.ALB_INGRESS_CLASS_ANNOTATION]
	if !ok || ingressClass != "alb" {
		log.Info(fmt.Sprintf("Ingres class annotation '%s' is either missing or not set as 'alb': aborting.", global.ALB_INGRESS_CLASS_ANNOTATION))
		return ctrl.Result{}, nil
	}

	// Make sure SSL is expected.
	serializedListenPorts, ok := ingress.Annotations[global.ALB_INGRESS_LISTEN_PORTS_ANNOTATION]
	if !ok || serializedListenPorts == "" {
		log.Info(fmt.Sprintf("Ingress does not define a '%s' annotation: aborting.", global.ALB_INGRESS_LISTEN_PORTS_ANNOTATION))
		return ctrl.Result{}, nil
	}

	var listenPorts []map[string]int32 // Expected JSON structure is an array of integer-valued maps [{'HTTP':0},{'HTTPS':0},...]
	err := json.Unmarshal([]byte(serializedListenPorts), &listenPorts)
	if err != nil {
		log.Error(err, "Could not deserialize contents of '%s' annotation.", global.ALB_INGRESS_LISTEN_PORTS_ANNOTATION)
		return ctrl.Result{}, nil
	}

	httpsExpected := false
	for _, listenPort := range listenPorts {
		_, ok := listenPort["HTTPS"]
		if ok {
			httpsExpected = true
			break
		}
	}

	ingressARNAnnotation, ingressHasARNAnnotation := ingress.Annotations[global.ALB_INGRESS_CERTIFICATE_ARN_ANNOTATION]

	if !httpsExpected {
		log.Info(fmt.Sprintf("'%s' annotation does not require HTTPS.", global.ALB_INGRESS_LISTEN_PORTS_ANNOTATION))

		if ingressHasARNAnnotation {
			log.Info("Removing ACM certificate ARNs from Ingress...")

			err = r.RemoveIngressCertificateAnnotation(ingress)
			if err != nil {
				log.Error(err, "Failed to remove ACM certificate ARN(s).")
				return ctrl.Result{}, err
			}
		}

		return ctrl.Result{}, nil
	}

	// Extract unique list of hosts from spec.
	hostNames := []string{}
	for _, rule := range ingress.Spec.Rules {
		if rule.Host == "" {
			continue
		}
		if !containsString(hostNames, rule.Host) {
			hostNames = append(hostNames, rule.Host)
		}
	}

	// Retrieve certificate ARNs for hosts by processing TLS certificates stored as K8S Secrets which have been processed by secret_controller and synced with ACM.
	secretList := &corev1.SecretList{}
	// Documentation on how to use ListOptions is thin on the ground. See 'Options' in https://pkg.go.dev/sigs.k8s.io/controller-runtime/pkg/client. Searching by field requires an index - see SetupWithManager().
	listErr := r.List(context.TODO(), secretList, client.MatchingFields{"type": string(corev1.SecretTypeTLS)})
	if listErr != nil {
		log.Error(listErr, "Could not list Secrets.")
		return ctrl.Result{}, listErr
	}
	var hasUnmatchedHostName bool
	certificateArns := []string{}
	for _, hostName := range hostNames {
		certificateArn, err := r.FindCertificateArnForHost(secretList.Items, hostName)
		if err != nil {
			// If we can't find an ARN for a given hostname, we can still save the ones we can find - but return an error so reconciliation is re-attempted.
			hasUnmatchedHostName = true
			continue
		}
		if !containsString(certificateArns, certificateArn) {
			certificateArns = append(certificateArns, certificateArn)
		}
	}

	// Update annotation.
	arnAnnotation := strings.Join(certificateArns, ",")
	if !ingressHasARNAnnotation || ingressARNAnnotation != arnAnnotation {
		log.Info("Adding ACM certificate ARNs to Ingress...")

		err = r.AddIngressCertificateAnnotation(ingress, arnAnnotation)
		if err != nil {
			log.Error(err, "Failed to persist ACM certificate ARN(s) back to Ingress.")
			return ctrl.Result{}, err
		}
	}

	if hasUnmatchedHostName {
		log.Info("At least one host name was not reconciled with a certificate ARN: will retry.")
		return ctrl.Result{RequeueAfter: defaultRequeueLatency}, nil
	}

	return ctrl.Result{}, nil
}

func (r *IngressReconciler) FindCertificateArnForHost(secrets []corev1.Secret, hostName string) (string, error) {

	// Generate the wildcard form of the hostName (at the same level) so we can match against wildcard certificates.
	wildcardHostName := r.ConvertToWildcardHost(hostName)

	for _, secret := range secrets {

		// Secret must have an ARN annotation, otherwise ignore it.
		certificateArn, ok := secret.Annotations[global.AGENT_CERTIFICATE_ARN_ANNOTATION]
		if !ok || certificateArn == "" {
			continue
		}

		// If the Secret has an expiry date, check it and ignore it if it has expired.
		expiryDateIso, ok := secret.Annotations[global.AGENT_CERTIFICATE_EXPIRY_DATE_ANNOTATION]
		if ok && expiryDateIso != "" {
			expiryDate, err := time.Parse(time.RFC3339, expiryDateIso)
			if err == nil {
				if time.Now().After(expiryDate) {
					continue
				}
			}
		}

		// secret_controller automatically extracts domains supported by each ACM-synced certificate from the SAN field (DNSName=%) and stores them as an annotation.
		domainNamesAnnotation, ok := secret.Annotations[global.AGENT_CERTIFICATE_DOMAIN_NAMES_ANNOTATION]
		if !ok || domainNamesAnnotation == "" {
			continue
		}

		domainNames := trimSpaceFromSliceElements(strings.Split(domainNamesAnnotation, ","))
		if containsStringIgnoringCase(domainNames, hostName) || containsStringIgnoringCase(domainNames, wildcardHostName) {
			return certificateArn, nil
		}

	}

	return "", fmt.Errorf("Certificate ARN could not be identified for host '%s'", hostName)
}

func (r *IngressReconciler) ConvertToWildcardHost(hostName string) string {

	components := strings.Split(hostName, ".")
	return "*." + strings.Join(components[1:], ".")

}

func (r *IngressReconciler) RemoveIngressCertificateAnnotation(ingress *networking.Ingress) error {
	delete(ingress.Annotations, global.ALB_INGRESS_CERTIFICATE_ARN_ANNOTATION)
	return r.Update(context.TODO(), ingress, &client.UpdateOptions{})
}

func (r *IngressReconciler) AddIngressCertificateAnnotation(ingress *networking.Ingress, certificateArns string) error {

	// Certificate ARN annotation for ALB can hold multiple (comma-separated) ARN values, see https://stackoverflow.com/questions/63433182/can-we-use-multiple-aws-acm-certificates-at-nginx-ingress-contoller-or-multiple
	ingress.Annotations[global.ALB_INGRESS_CERTIFICATE_ARN_ANNOTATION] = certificateArns
	return r.Update(context.TODO(), ingress, &client.UpdateOptions{})

}
