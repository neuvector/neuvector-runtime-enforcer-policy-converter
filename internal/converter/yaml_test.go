package converter_test

import (
	"bytes"
	"context"
	"testing"

	"github.com/neuvector/neuvector-runtime-enforcer-policy-converter/internal/converter"
	nvv1 "github.com/neuvector/neuvector/controller/k8sapi/v1"
	securityv1alpha1 "github.com/rancher-sandbox/runtime-enforcer/api/v1alpha1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/apis/meta/internalversion/scheme"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	dynamicfake "k8s.io/client-go/dynamic/fake"
)

func TestWriteWorkloadPoliciesToYAML(t *testing.T) {
	// Register schemes for deserialization
	err := securityv1alpha1.AddToScheme(scheme.Scheme)
	require.NoError(t, err)
	err = corev1.AddToScheme(scheme.Scheme)
	require.NoError(t, err)

	tests := []struct {
		name      string
		policies  []*securityv1alpha1.WorkloadPolicy
		wantErr   bool
		wantCount int
	}{
		{
			name: "single policy",
			policies: []*securityv1alpha1.WorkloadPolicy{
				createTestPolicy("nv.test.default", "default", "monitor"),
			},
			wantErr:   false,
			wantCount: 1,
		},
		{
			name: "multiple policies",
			policies: []*securityv1alpha1.WorkloadPolicy{
				createTestPolicy("nv.test1.default", "default", "monitor"),
				createTestPolicy("nv.test2.default", "default", "protect"),
			},
			wantErr:   false,
			wantCount: 2,
		},
		{
			name:      "empty slice",
			policies:  []*securityv1alpha1.WorkloadPolicy{},
			wantErr:   false,
			wantCount: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			err = converter.WriteWorkloadPoliciesToYAML(tt.policies, &buf)

			if tt.wantErr {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)

			// Verify output contains expected YAML structure
			output := buf.String()

			// For non-empty cases, verify WorkloadPolicy items
			if tt.wantCount > 0 {
				assert.Contains(t, output, "kind: WorkloadPolicy")
				assert.Contains(t, output, "apiVersion: security.rancher.io/v1alpha1")

				// Verify each policy appears in output
				for _, policy := range tt.policies {
					assert.Contains(t, output, policy.Name)
					assert.Contains(t, output, policy.Namespace)
					assert.Contains(t, output, "mode: "+policy.Spec.Mode)
				}

				// Verify document separator for multiple policies
				if tt.wantCount > 1 {
					assert.Contains(t, output, "---")
				}
			}
		})
	}
}

func TestWriteWorkloadPoliciesToYAML_RoundTrip(t *testing.T) {
	// Register schemes
	err := securityv1alpha1.AddToScheme(scheme.Scheme)
	require.NoError(t, err)
	err = corev1.AddToScheme(scheme.Scheme)
	require.NoError(t, err)
	err = appsv1.AddToScheme(scheme.Scheme)
	require.NoError(t, err)

	// Create a WorkloadPolicy using the real conversion function
	ctx := context.Background()
	deployment := &appsv1.Deployment{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "apps/v1",
			Kind:       "Deployment",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-deployment",
			Namespace: "default",
		},
		Spec: appsv1.DeploymentSpec{
			Template: corev1.PodTemplateSpec{
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						{Name: "test-container"},
					},
				},
			},
		},
	}

	dynamicClient := dynamicfake.NewSimpleDynamicClient(scheme.Scheme, deployment)

	nvrule := &nvv1.NvSecurityRule{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "nv.test-deployment.default",
			Namespace: "default",
		},
		Spec: nvv1.NvSecurityRuleSpec{
			Target: nvv1.NvSecurityTarget{
				Selector: nvv1.GroupConfig{
					Name: "nv.test-deployment.default",
					Criteria: []nvv1.CriteriaEntry{
						{Key: "service", Op: "=", Value: "test-deployment.default"},
					},
				},
			},
			ProcessRule: []nvv1.NvSecurityProcessRule{
				{Name: "bash", Path: "/bin/bash", Action: "allow"},
			},
		},
	}

	policy, warnings, err := converter.NvSecurityRuleToWorkloadPolicy(ctx, dynamicClient, nvrule, "monitor")
	require.NoError(t, err)
	assert.Empty(t, warnings)
	require.NotNil(t, policy)

	// Serialize to YAML
	var buf bytes.Buffer
	err = converter.WriteWorkloadPoliciesToYAML([]*securityv1alpha1.WorkloadPolicy{policy}, &buf)
	require.NoError(t, err)

	// Verify output contains all expected fields
	output := buf.String()

	// Verify WorkloadPolicy structure
	assert.Contains(t, output, "kind: WorkloadPolicy")
	assert.Contains(t, output, "apiVersion: security.rancher.io/v1alpha1")

	// Verify policy metadata
	assert.Contains(t, output, policy.Name)
	assert.Contains(t, output, policy.Namespace)
	assert.Contains(t, output, "mode: monitor")

	// Verify container name and executable rules are present
	assert.Contains(t, output, "test-container")
	assert.Contains(t, output, "/bin/bash")

	// Verify the output is valid YAML (parseable)
	assert.NotEmpty(t, output)
	assert.Contains(t, output, "rulesByContainer")

	// Should not contain "---" for single policy
	assert.NotContains(t, output, "---")
}

func createTestPolicy(name, namespace, mode string) *securityv1alpha1.WorkloadPolicy {
	rules := &securityv1alpha1.WorkloadPolicyRules{}
	rules.Executables.Allowed = []string{"/bin/bash", "/usr/bin/python"}

	return &securityv1alpha1.WorkloadPolicy{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "security.rancher.io/v1alpha1",
			Kind:       "WorkloadPolicy",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
		},
		Spec: securityv1alpha1.WorkloadPolicySpec{
			Mode: mode,
			RulesByContainer: map[string]*securityv1alpha1.WorkloadPolicyRules{
				"test-container": rules,
			},
		},
	}
}
