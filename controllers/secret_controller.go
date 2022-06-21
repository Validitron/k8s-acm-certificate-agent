/*

acm-certificate-agent
Centre for Digital Transformation of Health
Copyright Kit Huckvale 2022.

*/

//lint:file-ignore ST1005 Override golang error message formatting conventions.

package controllers

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/acm"
	"github.com/aws/aws-sdk-go-v2/service/acm/types"
	"github.com/google/uuid"
	corev1 "k8s.io/api/core/v1"
	k8serr "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"

	"Validitron/k8s-acm-certificate-agent/global"
)

// SecretReconciler reconciles built-in Secret objects.
type SecretReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

type CertificateDetails struct {
	SecretName     *string
	Namespace      *string
	Certificate    *CertificateWrapper
	Intermediates  []*CertificateWrapper
	CA             *CertificateWrapper
	PrivateKey     []byte
	CertificateArn *string
	CreatedAt      *string
}

type CertificateWrapper struct {
	PEM  *string
	x509 *x509.Certificate
}

func (r *SecretReconciler) SetupWithManager(mgr ctrl.Manager) error {
	// Tells the controller which object type this reconciler will handle.
	return ctrl.NewControllerManagedBy(mgr).
		For(&corev1.Secret{}).
		WithEventFilter(predicate.NewPredicateFuncs(func(obj client.Object) bool {

			// Only handle Secrets of type 'kubernetes.io/tls'
			secret, ok := obj.(*corev1.Secret)
			if ok {
				ok = (secret.Type == corev1.SecretTypeTLS)
			}

			return ok

		})).
		Complete(r)
}

func (r *SecretReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {

	log := log.FromContext(ctx)

	secret := &corev1.Secret{}
	if err := r.Client.Get(ctx, req.NamespacedName, secret); err != nil {
		if !k8serr.IsNotFound(err) {
			log.Error(err, "Unable to retrieve Secret.")
		}
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	if secret.Type != corev1.SecretTypeTLS {
		log.Info("Secret is not a TLS certificate: aborting.")
		return ctrl.Result{}, nil
	}

	// Object is marked for deletion - nothing to do (the operator never removes synced ACM certificates.)
	if !secret.ObjectMeta.DeletionTimestamp.IsZero() {
		log.Info("Secret marked for deletion: aborting.")
		return ctrl.Result{}, nil
	}

	// Detect if secret is annotated to enable certificate management.
	isManaged, ok := secret.Annotations[global.AGENT_ENABLED_ANNOTATION]
	if ok {
		ok, _ = strconv.ParseBool(isManaged)
	}
	if !ok {
		log.Info("Secret is not annotated to use certificate agent: aborting.")
		return ctrl.Result{}, nil
	}

	// Parse out leaf certificate, intermediates chain and private key from the K8s Secret.
	certificateDetails, err := r.ParseCertificateDetails(secret)
	if err != nil {
		log.Error(err, "Could not parse certificate: aborting.")
		return ctrl.Result{}, nil
	}

	// Check that certificate is in date.
	if certificateDetails.Certificate.x509.NotBefore.After(time.Now()) {
		log.Error(err, "Certificate is not yet valid: aborting.")
		return ctrl.Result{}, nil
	}
	if certificateDetails.Certificate.x509.NotAfter.Before(time.Now()) {
		log.Error(err, "Certificate has expired: aborting.")
		return ctrl.Result{}, nil
	}

	// Set up AWS connection.
	// The AWS go library automatically retrieves region, service account-linked role ARN and web identity token from environment variables. See https://aws.github.io/aws-sdk-go-v2/docs/configuring-sdk/
	// These will be automatically set for the pod in which the operator is running as long as the K8s service account is configured appropriately, see the project README and optionally https://docs.aws.amazon.com/eks/latest/userguide/specify-service-account-role.html
	cfg, err := config.LoadDefaultConfig(context.TODO())
	if err != nil {
		log.Error(err, "Failed to load AWS configuration.")
		return ctrl.Result{}, err
	}

	acmClient := acm.NewFromConfig(cfg)

	acmImportRequired := false
	arnUpdateRequired := false

	// If a certificate ARN annotation exists, see if the certificate exists and matches the serial number. If so, abort (imports to ACM are quota limited.)
	serialNumber := certificateDetails.Certificate.x509.SerialNumber
	if certificateDetails.CertificateArn != nil {
		input := acm.DescribeCertificateInput{CertificateArn: certificateDetails.CertificateArn}
		acmCertificate, err := acmClient.DescribeCertificate(context.TODO(), &input)
		if err == nil {

			acmCertSerialNumber, ok := new(big.Int).SetString(strings.ReplaceAll(*acmCertificate.Certificate.Serial, ":", ""), 16)
			// A certificate with the annotated ARN exists, and it matches on serial number, therefore nothing to do.
			if ok && serialNumber.Cmp(acmCertSerialNumber) == 0 {
				log.Error(err, "Certificate already exists in ACM: aborting.")
				return ctrl.Result{}, nil
			}

			// A certificate with the annotated ARN exists, but it does not match on serial number. (K8s certificate should always override ACM certificate therefore we import it to ACM without further BL required.)
			acmImportRequired = true
			arnUpdateRequired = false

			certificateDetails.CreatedAt = r.GetACMCertificateTag(acmClient, acmCertificate.Certificate.CertificateArn, "tron/createdAt")

		} else {
			if strings.Contains(err.Error(), "(ResourceNotFoundException)") {
				// Certificate does not exist in ACM, therefore reset ARN annotation. Don't set importRequired yet - we should search ACM certificate more broadly by domain name first (see below).
				certificateDetails.CertificateArn = nil
				acmImportRequired = false
				arnUpdateRequired = true

			} else {
				log.Error(err, "Failed to retrieve ACM certificate.")
				return ctrl.Result{}, err
			}
		}
	}

	if !acmImportRequired {

		// See if any existing ACM certificates match the current certificate. (ACM does not guard against duplicate certificate import, so we must do it manually.)
		domainName := certificateDetails.Certificate.x509.Subject.CommonName // ACM extracts domain from subject.CN
		domainMatches, err := r.FindACMCertificatesByDomain(acmClient, domainName)
		if err != nil {
			log.Error(err, "Failed to enumerate existing ACM certificate.")
			return ctrl.Result{}, err
		}

		// Assume we will need to import the certificate, unless we now find a match.
		acmImportRequired = true
		arnUpdateRequired = true

		for _, acmCertificate := range domainMatches {
			acmCertSerialNumber, ok := new(big.Int).SetString(strings.ReplaceAll(*acmCertificate.Certificate.Serial, ":", ""), 16)
			if ok && serialNumber.Cmp(acmCertSerialNumber) == 0 {
				certificateDetails.CertificateArn = acmCertificate.Certificate.CertificateArn
				acmImportRequired = false
				arnUpdateRequired = true
			}
		}

	}

	// Import certificate to ACM, if required
	if acmImportRequired {

		importInput := acm.ImportCertificateInput{
			Certificate:      []byte(*certificateDetails.Certificate.PEM),
			CertificateChain: []byte(*r.CertificateWrapperArrayToPEM(certificateDetails.Intermediates)),
			PrivateKey:       certificateDetails.PrivateKey,
			Tags:             r.CreateStandardTagArray(certificateDetails.CreatedAt),
		}
		if certificateDetails.CertificateArn != nil {
			importInput.CertificateArn = certificateDetails.CertificateArn
		}

		importResult, err := acmClient.ImportCertificate(context.TODO(), &importInput)
		if err != nil {
			log.Error(err, "ACM certificate import failed.")
			return ctrl.Result{}, err
		}

		certificateDetails.CertificateArn = importResult.CertificateArn
	}

	// Patch ROLE_ARN annotation, if required
	if arnUpdateRequired {
		if certificateDetails.CertificateArn == nil {
			err := errors.New("Certificate ARN update required but no ARN set.")
			log.Error(err, "Failed to persist ACM certificate ARN back to Secret.")
			return ctrl.Result{}, err
		}

		secret.Annotations[global.AGENT_CERTIFICATE_ARN_ANNOTATION] = *certificateDetails.CertificateArn
		secret.Annotations[global.AGENT_CERTIFICATE_SERIAL_NUMBER_ANNOTATION] = r.FormatX509SerialNumber(certificateDetails.Certificate.x509.SerialNumber)
		secret.Annotations[global.AGENT_CERTIFICATE_EXPIRES_ANNOTATION] = certificateDetails.Certificate.x509.NotAfter.Format(global.ISO_8601_FORMAT)

		// TODO - add other annotations e.g. expiry date/serial number.

		err = r.Client.Update(
			context.TODO(),
			secret,
			&client.UpdateOptions{},
		)

		if err != nil {
			log.Error(err, "Failed to persist ACM certificate ARN back to Secret.")
			return ctrl.Result{}, err
		}
	}

	return ctrl.Result{}, nil
}

func (r *SecretReconciler) ParseCertificateDetails(secret *corev1.Secret) (CertificateDetails, error) {

	certBytes, ok := secret.Data["tls.crt"]
	if !ok || len(certBytes) == 0 {
		return CertificateDetails{}, errors.New("'tls.crt' is missing or empty")
	}

	pkBytes, ok := secret.Data["tls.key"]
	if !ok || len(pkBytes) == 0 {
		return CertificateDetails{}, errors.New("'tls.key' is missing or empty")
	}

	// Not currently used.
	// Authority will not be submitted to ACM since roots must be distributed independently to be useful for trust (!).
	// Not all secrets are expected to have a ca.crt defined.
	/*
		caBytes, ok := secret.Data["ca.crt"]
		var ca *CertificateWrapper
		if ok && len(caBytes) > 0 {
			block, _ := pem.Decode(caBytes)
			if block == nil {
				return CertificateDetails{}, errors.New("Could not decode certificate within 'ca.crt'.")
			}
			certificate, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return CertificateDetails{}, errors.New("Could not parse certificate within 'tls.crt'.")
			}
			ca = &CertificateWrapper{
				PEM:  string(caBytes),
				x509: certificate,
			}
		}
	*/

	certString := string(certBytes)
	regex := regexp.MustCompile(`(?m)` + global.PEM_CERTIFICATE_BEGIN_TAG + `[\w\W]+?` + global.PEM_CERTIFICATE_END_TAG)

	certificates := []*CertificateWrapper{}

	matches := regex.FindAllString(certString, -1)
	for i, componentCertificate := range matches {
		block, _ := pem.Decode([]byte(componentCertificate))
		if block == nil {
			return CertificateDetails{}, fmt.Errorf("Could not decode certificate at index %d within 'tls.crt'.", i)
		}

		certificate, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return CertificateDetails{}, fmt.Errorf("Could not parse certificate at index %d within 'tls.crt'.", i)
		}
		certificates = append(certificates, &CertificateWrapper{
			PEM:  &componentCertificate,
			x509: certificate,
		})
	}

	// Find leaf certificate = the one whose subject is not *also* an issuer of another certificate.
	var leaf *CertificateWrapper
	for i, certificate := range certificates {
		subjectDN := certificate.x509.Subject.String()
		isIssuer := false
		for j, otherCertificate := range certificates {
			if i == j {
				continue
			}
			if otherCertificate.x509.Issuer.String() == subjectDN {
				isIssuer = true
				break
			}
		}
		if !isIssuer {
			leaf = certificate
			break
		}
	}

	// Construct intermediate chain (leafwards -> rootwards)
	var intermediates []*CertificateWrapper
	current := leaf
	for {
		issuer := r.FindIssuingCertificate(current, certificates)
		if issuer == nil {
			break
		}
		intermediates = append(intermediates, issuer)
		current = issuer
	}

	// Verify that intermediate chain is complete
	if len(intermediates) != len(matches)-1 {
		return CertificateDetails{}, errors.New("One or more certificates not incorporated into intermediate chain.")
	}

	// Retrieve certificate ARN, if set.
	certificateArn := secret.Annotations[global.AGENT_CERTIFICATE_ARN_ANNOTATION]

	output := &CertificateDetails{
		SecretName:     &secret.Name,
		Namespace:      &secret.Namespace,
		Certificate:    leaf,
		Intermediates:  intermediates,
		CA:             nil, /*ca*/
		PrivateKey:     pkBytes,
		CertificateArn: &certificateArn,
	}

	return *output, nil
}

func (r *SecretReconciler) FindIssuingCertificate(subjectCertificate *CertificateWrapper, certificatePool []*CertificateWrapper) *CertificateWrapper {
	issuerDN := subjectCertificate.x509.Issuer.String()
	for _, candidateCertificate := range certificatePool {
		if candidateCertificate.x509.Subject.String() == issuerDN {
			return candidateCertificate
		}
	}
	return nil
}

func (r *SecretReconciler) FindACMCertificatesByDomain(acmClient *acm.Client, domainName string) ([]*acm.DescribeCertificateOutput, error) {

	var output []*acm.DescribeCertificateOutput

	// AWS API for ACM provides no way (currently @v2.x) to search for certificates by domain, so we must iterate through.

	var nextToken string
	for {
		input := acm.ListCertificatesInput{
			MaxItems: aws.Int32(10),
		}
		if nextToken != "" {
			input.NextToken = aws.String(nextToken)
		}

		listOutput, err := acmClient.ListCertificates(context.TODO(), &input)
		if err != nil {
			return output, err
		}

		for _, acmCertificateSummary := range listOutput.CertificateSummaryList {
			if *acmCertificateSummary.DomainName == domainName {

				// Retrieve certificate details
				describeInput := acm.DescribeCertificateInput{
					CertificateArn: acmCertificateSummary.CertificateArn,
				}
				acmCertificate, err := acmClient.DescribeCertificate(context.TODO(), &describeInput)
				if err != nil {
					return output, err
				}

				output = append(output, acmCertificate)
			}
		}

		nextToken = *listOutput.NextToken
		if nextToken == "" {
			break
		}
	}

	return output, nil
}

func (r *SecretReconciler) CertificateWrapperArrayToPEM(wrapperArray []*CertificateWrapper) *string {
	var output string

	if len(wrapperArray) == 0 {
		return nil
	}

	for _, certificateWrapper := range wrapperArray {
		output += *certificateWrapper.PEM
	}

	return &output
}

func (r *SecretReconciler) GetACMCertificateTag(acmClient *acm.Client, certificateArn *string, tagKey string) *string {

	input := acm.ListTagsForCertificateInput{
		CertificateArn: certificateArn,
	}
	tags, err := acmClient.ListTagsForCertificate(context.TODO(), &input)
	if err != nil {
		return nil
	}

	for _, tag := range tags.Tags {
		if *tag.Key == tagKey {
			return tag.Value
		}
	}

	return nil
}

func (r *SecretReconciler) CreateStandardTagArray(createdAtString *string) []types.Tag {

	now := aws.String(time.Now().UTC().Format(global.ISO_8601_FORMAT))

	createModifiedTag := true

	if createdAtString == nil {
		createdAtString = now     // Why this weird format string? Because: reasons. (https://pkg.go.dev/time)	}
		createModifiedTag = false // No previous createdAt timestamp, therefore don't create a 'modifiedAt' tag.
	}

	output := []types.Tag{
		{
			Key:   aws.String("tron/correlationId"),
			Value: aws.String(strings.ReplaceAll(base64.StdEncoding.EncodeToString([]byte(uuid.New().String())), "=", "")),
		},
		{
			Key:   aws.String("tron/createdBy"),
			Value: aws.String(global.PACKAGE_NAME),
		},
		{
			Key:   aws.String("tron/createdAt"),
			Value: createdAtString,
		},
	}

	if createModifiedTag {
		output = append(output, types.Tag{
			Key:   aws.String("tron/modifiedAt"),
			Value: now,
		})
	}

	return output
}

func (r *SecretReconciler) FormatX509SerialNumber(number *big.Int) string {
	hex := number.Text(16)

	if len(hex)%2 > 0 {
		hex = "0" + hex
	}

	var output string
	for i, char := range hex {
		if i > 0 && i%2 == 0 {
			output = output + ":"
		}
		output = output + string(char)
	}

	return output
}
