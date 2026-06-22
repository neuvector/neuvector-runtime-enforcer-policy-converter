//go:build e2e

package e2e_test

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"testing"

	securityv1alpha1 "github.com/rancher-sandbox/runtime-enforcer/api/v1alpha1"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	sigsyaml "sigs.k8s.io/yaml"

	"sigs.k8s.io/e2e-framework/klient/k8s/resources"
	"sigs.k8s.io/e2e-framework/pkg/envconf"
)

const (
	testWorkloadName  = "e2e-test-app"
	testWorkloadImage = "registry.k8s.io/pause:3.9"
	testContainerName = "app"
)

type contextKey string

// ---- k8s client setup ----

func SetupSharedK8sClient(ctx context.Context, t *testing.T, config *envconf.Config) context.Context {
	t.Helper()
	r, err := resources.New(config.Client().RESTConfig())
	require.NoError(t, err)
	return context.WithValue(ctx, contextKey("client"), r)
}

func getClient(ctx context.Context) *resources.Resources {
	return ctx.Value(contextKey("client")).(*resources.Resources)
}

func createNamespace(ctx context.Context, t *testing.T, name string) {
	t.Helper()
	err := getClient(ctx).Create(ctx, &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{Name: name},
	})
	require.NoError(t, err)
}

func deleteNamespace(ctx context.Context, t *testing.T, name string) {
	t.Helper()
	err := getClient(ctx).Delete(ctx, &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{Name: name},
	})
	require.NoError(t, err)
}

// ---- converter CLI helpers ----

// runConverter executes the converter binary targeting the cluster identified by kubeconfigFile.
// mode maps to --mode, output maps to --output, inputFiles are the positional file arguments.
// Returns (stdout, stderr, error) — error is non-nil on non-zero exit.
func runConverter(t *testing.T, kubeconfigFile, mode, output string, inputFiles ...string) (string, string, error) {
	t.Helper()
	args := []string{"convert", "--mode", mode, "--output", output}
	args = append(args, inputFiles...)
	cmd := exec.Command(converterBin, args...)
	cmd.Env = append(os.Environ(), "KUBECONFIG="+kubeconfigFile)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	return stdout.String(), stderr.String(), err
}

// parseWorkloadPolicy unmarshals the YAML output of the converter into a WorkloadPolicy.
func parseWorkloadPolicy(t *testing.T, yamlStr string) *securityv1alpha1.WorkloadPolicy {
	t.Helper()
	var policy securityv1alpha1.WorkloadPolicy
	require.NoError(t, sigsyaml.Unmarshal([]byte(yamlStr), &policy))
	return &policy
}
