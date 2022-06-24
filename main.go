/*

acm-certificate-agent
Centre for Digital Transformation of Health
Copyright Kit Huckvale 2022.

*/

//lint:file-ignore ST1005 Override golang logging/error formatting conventions (use Validitron standard which is 'Sentence case with punctuation.')

package main

import (
	"flag"
	"os"
	"strconv"

	_ "k8s.io/client-go/plugin/pkg/client/auth"

	cm "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	networking "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"

	"Validitron/k8s-acm-certificate-agent/controllers"
)

var (
	// We use a single scheme across all controllers for simplicity.
	scheme   = runtime.NewScheme()
	setupLog = ctrl.Log.WithName("setup")
)

const (
	ENABLE_CERTIFICATE_SYNC   string = "ENABLE_CERTIFICATE_SYNC"
	ENABLE_INGRESS_DECORATION string = "ENABLE_INGRESS_DECORATION"
)

func init() {

	//Add scheme for build in types (Secret).
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))

	// Add scheme for networking types (Ingress).
	utilruntime.Must(networking.AddToScheme(scheme))

	//Add scheme for cert-manager API types (Certificate).
	utilruntime.Must(cm.AddToScheme(scheme))

}

func main() {
	var metricsAddr string
	var enableLeaderElection bool
	var probeAddr string
	flag.StringVar(&metricsAddr, "metrics-bind-address", ":8080", "The address the metric endpoint binds to.")
	flag.StringVar(&probeAddr, "health-probe-bind-address", ":8081", "The address the probe endpoint binds to.")
	flag.BoolVar(&enableLeaderElection, "leader-elect", false,
		"Enable leader election for controller manager. "+
			"Enabling this will ensure there is only one active controller manager.")
	opts := zap.Options{
		Development: true,
	}
	opts.BindFlags(flag.CommandLine)
	flag.Parse()

	// NB that when there are multiple controllers, logging must be further configured so that log entries are correctly annotated with controller details. See the SetupWithManager methods for each controller.
	ctrl.SetLogger(zap.New(zap.UseFlagOptions(&opts)))

	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
		//Namespace: // No namespace is defined = cluster-scoped.
		Scheme:                 scheme,
		MetricsBindAddress:     metricsAddr,
		Port:                   9443,
		HealthProbeBindAddress: probeAddr,
		LeaderElection:         enableLeaderElection,
		LeaderElectionID:       "d4b9aab7.validitron.io",
	})
	if err != nil {
		setupLog.Error(err, "Unable to start manager.")
		os.Exit(1)
	}

	if getBooleanEnv(ENABLE_CERTIFICATE_SYNC) {

		if err = (&controllers.SecretReconciler{
			Client: mgr.GetClient(),
			Scheme: mgr.GetScheme(),
		}).SetupWithManager(mgr); err != nil {
			setupLog.Error(err, "Unable to create Secret reconciler.", "controller", "Secret")
			os.Exit(1)
		}

		if err = (&controllers.CertificateReconciler{
			Client: mgr.GetClient(),
			Scheme: mgr.GetScheme(),
		}).SetupWithManager(mgr); err != nil {
			setupLog.Error(err, "Unable to create Certificate reconciler.", "controller", "Certificate")
			os.Exit(1)
		}

	}

	if getBooleanEnv(ENABLE_INGRESS_DECORATION) {

		if err = (&controllers.IngressReconciler{
			Client: mgr.GetClient(),
			Scheme: mgr.GetScheme(),
		}).SetupWithManager(mgr); err != nil {
			setupLog.Error(err, "Unable to create ingress reconciler.", "controller", "Ingress")
			os.Exit(1)
		}

	}

	if err := mgr.AddHealthzCheck("healthz", healthz.Ping); err != nil {
		setupLog.Error(err, "Unable to set up health check.")
		os.Exit(1)
	}
	if err := mgr.AddReadyzCheck("readyz", healthz.Ping); err != nil {
		setupLog.Error(err, "Unable to set up ready check.")
		os.Exit(1)
	}

	setupLog.Info("Starting manager...")
	if err := mgr.Start(ctrl.SetupSignalHandler()); err != nil {
		setupLog.Error(err, "Problem running manager.")
		os.Exit(1)
	}
}

func getBooleanEnv(key string) bool {
	result, _ := strconv.ParseBool(os.Getenv(key))
	return result
}
