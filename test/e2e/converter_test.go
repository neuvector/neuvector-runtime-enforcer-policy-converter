//go:build e2e

package e2e_test

import (
	"context"
	"testing"

	securityv1alpha1 "github.com/rancher-sandbox/runtime-enforcer/api/v1alpha1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"sigs.k8s.io/e2e-framework/klient/decoder"
	"sigs.k8s.io/e2e-framework/pkg/envconf"
	"sigs.k8s.io/e2e-framework/pkg/features"
	"sigs.k8s.io/e2e-framework/pkg/types"
)

const (
	nsMultiWorkloads  = "e2e-converter-multi"
	nsPodNotSupported = "e2e-converter-pod"
)

func TestConverterHappyPath(t *testing.T)         { testEnv.Test(t, happyPathFeature()) }
func TestConverterNegativePath(t *testing.T)      { testEnv.Test(t, negativePathFeature()) }
func TestConverterMultipleWorkloads(t *testing.T) { testEnv.Test(t, multipleWorkloadsFeature()) }
func TestConverterPodNotSupported(t *testing.T)   { testEnv.Test(t, podNotSupportedFeature()) }

// happyPathFeature uses testdata/simple.yaml, which references the kube-proxy DaemonSet
// that is always present in kube-system on a KinD cluster. No workload setup is required.
func happyPathFeature() types.Feature {
	return features.New("converter CLI: convert kube-proxy NvSecurityRule using testdata/simple.yaml").
		Assess("produces a valid WorkloadPolicy",
			func(ctx context.Context, t *testing.T, config *envconf.Config) context.Context {
				stdout, _, err := runConverter(t, config.KubeconfigFile(), "monitor", "-", "testdata/simple.yaml")
				require.NoError(t, err)

				policy := parseWorkloadPolicy(t, stdout)
				assert.Equal(t, "nv.kube-proxy.kube-system", policy.Name)
				assert.Equal(t, "kube-system", policy.Namespace)
				assert.Equal(t, securityv1alpha1.PolicyModeMonitor, policy.Spec.Mode)
				require.Len(t, policy.Spec.RulesByContainer, 1)
				containerRules, ok := policy.Spec.RulesByContainer["kube-proxy"]
				require.True(t, ok)
				require.NotNil(t, containerRules)
				assert.NotEmpty(t, containerRules.Executables.Allowed)
				return ctx
			}).
		Feature()
}

// negativePathFeature uses testdata/nvrule-notfound.yaml, which references a workload that
// does not exist in the default namespace of a KinD cluster.
func negativePathFeature() types.Feature {
	return features.New("converter CLI: error when workload does not exist").
		Assess("exits non-zero and reports no workload found",
			func(ctx context.Context, t *testing.T, config *envconf.Config) context.Context {
				_, stderr, err := runConverter(
					t,
					config.KubeconfigFile(),
					"monitor",
					"-",
					"testdata/nvrule-notfound.yaml",
				)
				require.Error(t, err)
				assert.Contains(t, stderr, "no workload found")
				return ctx
			}).
		Feature()
}

func multipleWorkloadsFeature() types.Feature {
	return features.New("converter CLI: error when multiple workloads share the same name").
		Setup(SetupSharedK8sClient).
		Setup(func(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
			createNamespace(ctx, t, nsMultiWorkloads)
			require.NoError(
				t,
				decoder.ApplyWithManifestDir(
					ctx,
					getClient(ctx),
					"testdata",
					"deployment.yaml",
					nil,
					decoder.MutateNamespace(nsMultiWorkloads),
				),
			)
			require.NoError(
				t,
				decoder.ApplyWithManifestDir(
					ctx,
					getClient(ctx),
					"testdata",
					"daemonset.yaml",
					nil,
					decoder.MutateNamespace(nsMultiWorkloads),
				),
			)
			return ctx
		}).
		Assess("exits non-zero and reports multiple workloads found",
			func(ctx context.Context, t *testing.T, config *envconf.Config) context.Context {
				_, stderr, err := runConverter(
					t,
					config.KubeconfigFile(),
					"monitor",
					"-",
					"testdata/nvrule-multiple-workloads.yaml",
				)
				require.Error(t, err)
				assert.Contains(t, stderr, "multiple workloads found")
				return ctx
			}).
		Teardown(func(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
			deleteNamespace(ctx, t, nsMultiWorkloads)
			return ctx
		}).
		Feature()
}

func podNotSupportedFeature() types.Feature {
	return features.New("converter CLI: error when workload is a bare Pod").
		Setup(SetupSharedK8sClient).
		Setup(func(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
			createNamespace(ctx, t, nsPodNotSupported)
			require.NoError(
				t,
				decoder.ApplyWithManifestDir(
					ctx,
					getClient(ctx),
					"testdata",
					"pod.yaml",
					nil,
					decoder.MutateNamespace(nsPodNotSupported),
				),
			)
			return ctx
		}).
		Assess("exits non-zero and reports pod not supported",
			func(ctx context.Context, t *testing.T, config *envconf.Config) context.Context {
				_, stderr, err := runConverter(t, config.KubeconfigFile(), "monitor", "-", "testdata/nvrule-pod.yaml")
				require.Error(t, err)
				assert.Contains(t, stderr, "doesn't support NeuVector service created from pod")
				return ctx
			}).
		Teardown(func(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
			deleteNamespace(ctx, t, nsPodNotSupported)
			return ctx
		}).
		Feature()
}
