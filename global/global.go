package global

import (
	"time"
)

const (
	PACKAGE_NAME string = "acm-certificate-agent"
	DOMAIN_NAME  string = "validitron.io"
	FULL_NAME    string = PACKAGE_NAME + "." + DOMAIN_NAME

	AGENT_ENABLED_ANNOTATION                   string = FULL_NAME + "/enabled"
	AGENT_INHERITS_FROM_ANNOTATION             string = FULL_NAME + "/inherits-from"
	AGENT_CERTIFICATE_ARN_ANNOTATION           string = FULL_NAME + "/certificate-arn"
	AGENT_CERTIFICATE_DOMAIN_NAMES_ANNOTATION  string = FULL_NAME + "/domains"
	AGENT_CERTIFICATE_SERIAL_NUMBER_ANNOTATION string = FULL_NAME + "/serial-number"
	AGENT_CERTIFICATE_EXPIRY_DATE_ANNOTATION   string = FULL_NAME + "/expires"

	ALB_INGRESS_CLASS_ANNOTATION           string = "kubernetes.io/ingress.class"
	ALB_INGRESS_LISTEN_PORTS_ANNOTATION    string = "alb.ingress.kubernetes.io/listen-ports"
	ALB_INGRESS_CERTIFICATE_ARN_ANNOTATION string = "alb.ingress.kubernetes.io/certificate-arn"

	CERTIFICATE_STATUS_FAILED   string = "Failed"
	CERTIFICATE_STATUS_EXPIRED  string = "Expired"
	CERTIFICATE_STATUS_INACTIVE string = "Inactive"

	PEM_CERTIFICATE_BEGIN_TAG string = "-----BEGIN CERTIFICATE-----"
	PEM_CERTIFICATE_END_TAG   string = "-----END CERTIFICATE-----"

	ISO_8601_FORMAT string = "2006-01-02T15:04:05+07:00" // Why this arbitrary string? Because: reasons. See https://pkg.go.dev/time#pkg-constants

	DEFAULT_REQUEUE_LATENCY = 15 * time.Second
)
