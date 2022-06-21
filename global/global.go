package global

import (
	"time"
)

const (
	PACKAGE_NAME string = "acm-certificate-agent"
	DOMAIN_NAME  string = "validitron.io"

	AGENT_ENABLED_ANNOTATION                   string = PACKAGE_NAME + "." + DOMAIN_NAME + "/enabled"
	AGENT_CONFIGURATION_MODE_ANNOTATION        string = PACKAGE_NAME + "." + DOMAIN_NAME + "/configuration-mode"
	AGENT_CERTIFICATE_ARN_ANNOTATION           string = PACKAGE_NAME + "." + DOMAIN_NAME + "/certificate-arn"
	AGENT_CERTIFICATE_SERIAL_NUMBER_ANNOTATION string = PACKAGE_NAME + "." + DOMAIN_NAME + "/serial-number"
	AGENT_CERTIFICATE_EXPIRES_ANNOTATION       string = PACKAGE_NAME + "." + DOMAIN_NAME + "/expires"

	CERTIFICATE_STATUS_FAILED   string = "Failed"
	CERTIFICATE_STATUS_EXPIRED  string = "Expired"
	CERTIFICATE_STATUS_INACTIVE string = "Inactive"

	PEM_CERTIFICATE_BEGIN_TAG string = "-----BEGIN CERTIFICATE-----"
	PEM_CERTIFICATE_END_TAG   string = "-----END CERTIFICATE-----"

	ISO_8601_FORMAT string = "2006-01-02T15:04:05Z07:00"

	DEFAULT_REQUEUE_LATENCY = 15 * time.Second
)
