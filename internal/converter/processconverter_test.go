package converter_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/neuvector/neuvector-runtime-enforcer-policy-converter/internal/converter"
	nvv1 "github.com/neuvector/neuvector/controller/k8sapi/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	dynamicfake "k8s.io/client-go/dynamic/fake"
)

func TestReadNvSecurityRules(t *testing.T) {
	tests := []struct {
		name        string
		filepath    string
		wantErr     bool
		wantCount   int
		description string
	}{
		{
			name:        "valid simple yaml",
			filepath:    "testdata/simple.yaml",
			wantErr:     false,
			wantCount:   1,
			description: "should successfully read a valid NvSecurityRuleList exported from NeuVector",
		},
		{
			name:        "valid simple yaml",
			filepath:    "testdata/simple-crd.yaml",
			wantErr:     false,
			wantCount:   1,
			description: "should successfully read a valid NvSecurityRule CRD",
		},
		{
			name:        "non-existent file",
			filepath:    "testdata/does-not-exist.yaml",
			wantErr:     true,
			wantCount:   0,
			description: "should return error when file doesn't exist",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Convert relative path to absolute for the test
			testFilePath := filepath.Join("../../internal/converter", tt.filepath)
			if !filepath.IsAbs(tt.filepath) && tt.filepath != "testdata/does-not-exist.yaml" {
				cwd, err := os.Getwd()
				if err != nil {
					t.Fatalf("failed to get working directory: %v", err)
				}
				testFilePath = filepath.Join(cwd, testFilePath)
			} else if tt.filepath == "testdata/does-not-exist.yaml" {
				testFilePath = tt.filepath
			}

			rules, err := converter.ReadNvSecurityRules(testFilePath)

			// Check error expectation
			if (err != nil) != tt.wantErr {
				t.Errorf("ReadNvSecurityRules() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			// Check count of returned rules
			if got := len(rules); got != tt.wantCount {
				t.Errorf("ReadNvSecurityRules() returned %d rules, want %d", got, tt.wantCount)
			}

			// Additional validation for successful cases
			if !tt.wantErr && len(rules) > 0 {
				validateSimpleYamlRule(t, rules[0])
			}
		})
	}
}

// validateSimpleYamlRule validates the structure of a rule loaded from simple.yaml.
func validateSimpleYamlRule(t *testing.T, rule *nvv1.NvSecurityRule) {
	t.Helper()

	// Validate metadata
	if rule.Name != "nv.kube-proxy.kube-system" {
		t.Errorf("expected rule name 'nv.kube-proxy.kube-system', got '%s'", rule.Name)
	}

	if rule.Namespace != "kube-system" {
		t.Errorf("expected namespace 'kube-system', got '%s'", rule.Namespace)
	}

	if rule.Kind != "NvSecurityRule" {
		t.Errorf("expected kind 'NvSecurityRule', got '%s'", rule.Kind)
	}

	// Validate process rules exist
	if len(rule.Spec.ProcessRule) == 0 {
		t.Error("expected process rules to be present")
	}

	// Validate first process rule
	if len(rule.Spec.ProcessRule) > 0 {
		firstProcess := rule.Spec.ProcessRule[0]
		if firstProcess.Name != "ip6tables" {
			t.Errorf("expected first process name 'ip6tables', got '%s'", firstProcess.Name)
		}
		if firstProcess.Path != "/usr/sbin/xtables-nft-multi" {
			t.Errorf("expected first process path '/usr/sbin/xtables-nft-multi', got '%s'", firstProcess.Path)
		}
		if firstProcess.Action != "allow" {
			t.Errorf("expected first process action 'allow', got '%s'", firstProcess.Action)
		}
	}

	// Validate process profile
	if rule.Spec.ProcessProfile == nil {
		t.Error("expected process profile to be present")
	} else {
		if rule.Spec.ProcessProfile.Baseline == nil || *rule.Spec.ProcessProfile.Baseline != "zero-drift" {
			t.Error("expected baseline to be 'zero-drift'")
		}
		if rule.Spec.ProcessProfile.Mode == nil || *rule.Spec.ProcessProfile.Mode != "Discover" {
			t.Error("expected mode to be 'Discover'")
		}
	}

	// Validate target
	if rule.Spec.Target.Selector.Name != "nv.kube-proxy.kube-system" {
		t.Errorf("expected target selector name 'nv.kube-proxy.kube-system', got '%s'", rule.Spec.Target.Selector.Name)
	}
}

func TestParseNvServiceName(t *testing.T) {
	tests := []struct {
		name      string
		inputName string
		namespace string
		want      string
		wantErr   bool
	}{
		{
			name:      "name with nv prefix and namespace suffix",
			inputName: "nv.kube-proxy.kube-system",
			namespace: "kube-system",
			want:      "kube-proxy",
			wantErr:   false,
		},
		{
			name:      "complex service name",
			inputName: "nv.my-app-service.production",
			namespace: "production",
			want:      "my-app-service",
			wantErr:   false,
		},
		{
			name:      "minimal valid name",
			inputName: "nv.service.ns",
			namespace: "ns",
			want:      "service",
			wantErr:   false,
		},
		{
			name:      "missing nv prefix",
			inputName: "my-service.default",
			namespace: "default",
			want:      "",
			wantErr:   true,
		},
		{
			name:      "missing namespace suffix",
			inputName: "nv.my-service",
			namespace: "default",
			want:      "",
			wantErr:   true,
		},
		{
			name:      "wrong namespace suffix",
			inputName: "nv.my-service.prod",
			namespace: "staging",
			want:      "",
			wantErr:   true,
		},
		{
			name:      "empty name",
			inputName: "",
			namespace: "default",
			want:      "",
			wantErr:   true,
		},
		{
			name:      "only nv prefix with empty namespace - empty workload",
			inputName: "nv.",
			namespace: "",
			want:      "",
			wantErr:   true,
		},
		{
			name:      "service name equals namespace",
			inputName: "nv.default.default",
			namespace: "default",
			want:      "default",
			wantErr:   false,
		},
		{
			name:      "not recommended service name with dot",
			inputName: "nv.default.default.default.namespace",
			namespace: "namespace",
			want:      "default.default.default",
			wantErr:   false,
		},
		{
			name:      "workload name is only dots - not empty after trim",
			inputName: "nv...namespace",
			namespace: "namespace",
			want:      ".",
			wantErr:   false,
		},
		{
			name:      "empty workload after trim - whitespace only",
			inputName: "nv.   .default",
			namespace: "default",
			want:      "",
			wantErr:   true,
		},
		{
			name:      "workload name with leading/trailing spaces",
			inputName: "nv. service .namespace",
			namespace: "namespace",
			want:      "service",
			wantErr:   false,
		},
		{
			name:      "workload with leading dot after prefix removal",
			inputName: "nv..kube-system.kube-system",
			namespace: "kube-system",
			want:      ".kube-system",
			wantErr:   false,
		},
		{
			name:      "exact pattern nv.<namespace>.<namespace> results in namespace name",
			inputName: "nv.ns.ns",
			namespace: "ns",
			want:      "ns",
			wantErr:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := converter.ParseNvServiceName(tt.inputName, tt.namespace)
			if (err != nil) != tt.wantErr {
				t.Errorf(
					"ParseNvServiceName(%q, %q) error = %v, wantErr %v",
					tt.inputName,
					tt.namespace,
					err,
					tt.wantErr,
				)
				return
			}
			if got != tt.want {
				t.Errorf("ParseNvServiceName(%q, %q) = %q, want %q", tt.inputName, tt.namespace, got, tt.want)
			}
		})
	}
}

func TestSearchContainerName(t *testing.T) {
	tests := []struct {
		name          string
		workloadName  string
		namespace     string
		setupObjects  []runtime.Object
		wantContainer string
		wantKind      string
		wantErr       bool
		errContains   string
	}{
		{
			name:         "deployment with single container",
			workloadName: "myapp",
			namespace:    "default",
			setupObjects: []runtime.Object{
				newUnstructuredDeployment("myapp", "default", []string{"app-container"}),
			},
			wantContainer: "app-container",
			wantKind:      "Deployment",
			wantErr:       false,
		},
		{
			name:         "daemonset with single container",
			workloadName: "system-daemon",
			namespace:    "kube-system",
			setupObjects: []runtime.Object{
				newUnstructuredDaemonSet("system-daemon", "kube-system", []string{"daemon"}),
			},
			wantContainer: "daemon",
			wantKind:      "DaemonSet",
			wantErr:       false,
		},
		{
			name:         "statefulset with single container",
			workloadName: "database",
			namespace:    "default",
			setupObjects: []runtime.Object{
				newUnstructuredStatefulSet("database", "default", []string{"db"}),
			},
			wantContainer: "db",
			wantKind:      "StatefulSet",
			wantErr:       false,
		},
		{
			name:         "replicaset with single container",
			workloadName: "myapp-rs",
			namespace:    "default",
			setupObjects: []runtime.Object{
				newUnstructuredReplicaSet("myapp-rs", "default", []string{"app"}),
			},
			wantContainer: "app",
			wantKind:      "ReplicaSet",
			wantErr:       false,
		},
		{
			name:         "job with single container",
			workloadName: "batch-job",
			namespace:    "default",
			setupObjects: []runtime.Object{
				newUnstructuredJob("batch-job", "default", []string{"job-container"}),
			},
			wantContainer: "job-container",
			wantKind:      "Job",
			wantErr:       false,
		},
		{
			name:         "cronjob with single container",
			workloadName: "backup-job",
			namespace:    "default",
			setupObjects: []runtime.Object{
				newUnstructuredCronJob("backup-job", "default", []string{"backup"}),
			},
			wantContainer: "backup",
			wantKind:      "CronJob",
			wantErr:       false,
		},
		{
			name:         "pod with single container",
			workloadName: "standalone-pod",
			namespace:    "default",
			setupObjects: []runtime.Object{
				newUnstructuredPod("standalone-pod", "default", []string{"main"}),
			},
			wantContainer: "main",
			wantKind:      "Pod",
			wantErr:       false,
		},
		{
			name:         "deployment with multiple containers",
			workloadName: "myapp",
			namespace:    "default",
			setupObjects: []runtime.Object{
				newUnstructuredDeployment("myapp", "default", []string{"app", "sidecar"}),
			},
			wantErr:     true,
			errContains: "multiple containers",
		},
		{
			name:         "multiple workload types with same name",
			workloadName: "myapp",
			namespace:    "default",
			setupObjects: []runtime.Object{
				newUnstructuredDeployment("myapp", "default", []string{"app"}),
				newUnstructuredPod("myapp", "default", []string{"app"}),
			},
			wantErr:     true,
			errContains: "multiple workloads found",
		},
		{
			name:         "no workload found",
			workloadName: "nonexistent",
			namespace:    "default",
			setupObjects: []runtime.Object{},
			wantErr:      true,
			errContains:  "no workload found",
		},
		{
			name:         "deployment with three containers",
			workloadName: "complex-app",
			namespace:    "default",
			setupObjects: []runtime.Object{
				newUnstructuredDeployment("complex-app", "default", []string{"app", "sidecar", "init"}),
			},
			wantErr:     true,
			errContains: "multiple containers (3)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dynamicClient := dynamicfake.NewSimpleDynamicClient(runtime.NewScheme(), tt.setupObjects...)
			ctx := context.Background()

			gotContainer, gotKind, err := converter.SearchContainerName(
				ctx,
				dynamicClient,
				tt.workloadName,
				tt.namespace,
			)

			if (err != nil) != tt.wantErr {
				t.Errorf("SearchContainerName() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if tt.wantErr && tt.errContains != "" {
				if !strings.Contains(err.Error(), tt.errContains) {
					t.Errorf(
						"SearchContainerName() error = %v, should contain %q",
						err,
						tt.errContains,
					)
				}
			}

			if !tt.wantErr {
				if gotContainer != tt.wantContainer {
					t.Errorf(
						"SearchContainerName() containerName = %v, want %v",
						gotContainer,
						tt.wantContainer,
					)
				}
				if gotKind != tt.wantKind {
					t.Errorf(
						"SearchContainerName() kind = %v, want %v",
						gotKind,
						tt.wantKind,
					)
				}
			}
		})
	}
}

// Helper functions to create unstructured objects for testing

func newUnstructuredDeployment(name, namespace string, containerNames []string) *unstructured.Unstructured {
	containers := make([]interface{}, len(containerNames))
	for i, cn := range containerNames {
		containers[i] = map[string]interface{}{"name": cn}
	}

	return &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "apps/v1",
			"kind":       "Deployment",
			"metadata": map[string]interface{}{
				"name":      name,
				"namespace": namespace,
			},
			"spec": map[string]interface{}{
				"template": map[string]interface{}{
					"spec": map[string]interface{}{
						"containers": containers,
					},
				},
			},
		},
	}
}

func newUnstructuredDaemonSet(name, namespace string, containerNames []string) *unstructured.Unstructured {
	containers := make([]interface{}, len(containerNames))
	for i, cn := range containerNames {
		containers[i] = map[string]interface{}{"name": cn}
	}

	return &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "apps/v1",
			"kind":       "DaemonSet",
			"metadata": map[string]interface{}{
				"name":      name,
				"namespace": namespace,
			},
			"spec": map[string]interface{}{
				"template": map[string]interface{}{
					"spec": map[string]interface{}{
						"containers": containers,
					},
				},
			},
		},
	}
}

func newUnstructuredStatefulSet(name, namespace string, containerNames []string) *unstructured.Unstructured {
	containers := make([]interface{}, len(containerNames))
	for i, cn := range containerNames {
		containers[i] = map[string]interface{}{"name": cn}
	}

	return &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "apps/v1",
			"kind":       "StatefulSet",
			"metadata": map[string]interface{}{
				"name":      name,
				"namespace": namespace,
			},
			"spec": map[string]interface{}{
				"template": map[string]interface{}{
					"spec": map[string]interface{}{
						"containers": containers,
					},
				},
			},
		},
	}
}

func newUnstructuredReplicaSet(name, namespace string, containerNames []string) *unstructured.Unstructured {
	containers := make([]interface{}, len(containerNames))
	for i, cn := range containerNames {
		containers[i] = map[string]interface{}{"name": cn}
	}

	return &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "apps/v1",
			"kind":       "ReplicaSet",
			"metadata": map[string]interface{}{
				"name":      name,
				"namespace": namespace,
			},
			"spec": map[string]interface{}{
				"template": map[string]interface{}{
					"spec": map[string]interface{}{
						"containers": containers,
					},
				},
			},
		},
	}
}

func newUnstructuredJob(name, namespace string, containerNames []string) *unstructured.Unstructured {
	containers := make([]interface{}, len(containerNames))
	for i, cn := range containerNames {
		containers[i] = map[string]interface{}{"name": cn}
	}

	return &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "batch/v1",
			"kind":       "Job",
			"metadata": map[string]interface{}{
				"name":      name,
				"namespace": namespace,
			},
			"spec": map[string]interface{}{
				"template": map[string]interface{}{
					"spec": map[string]interface{}{
						"containers": containers,
					},
				},
			},
		},
	}
}

func newUnstructuredCronJob(name, namespace string, containerNames []string) *unstructured.Unstructured {
	containers := make([]interface{}, len(containerNames))
	for i, cn := range containerNames {
		containers[i] = map[string]interface{}{"name": cn}
	}

	return &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "batch/v1",
			"kind":       "CronJob",
			"metadata": map[string]interface{}{
				"name":      name,
				"namespace": namespace,
			},
			"spec": map[string]interface{}{
				"jobTemplate": map[string]interface{}{
					"spec": map[string]interface{}{
						"template": map[string]interface{}{
							"spec": map[string]interface{}{
								"containers": containers,
							},
						},
					},
				},
			},
		},
	}
}

func newUnstructuredPod(name, namespace string, containerNames []string) *unstructured.Unstructured {
	containers := make([]interface{}, len(containerNames))
	for i, cn := range containerNames {
		containers[i] = map[string]interface{}{"name": cn}
	}

	return &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "v1",
			"kind":       "Pod",
			"metadata": map[string]interface{}{
				"name":      name,
				"namespace": namespace,
			},
			"spec": map[string]interface{}{
				"containers": containers,
			},
		},
	}
}

// newNvSecurityRule creates a test NvSecurityRule with the given parameters
func newNvSecurityRule(name, namespace, serviceName string, processRules []nvv1.NvSecurityProcessRule) *nvv1.NvSecurityRule {
	baseline := "zero-drift"
	mode := "Discover"

	return &nvv1.NvSecurityRule{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
		},
		Spec: nvv1.NvSecurityRuleSpec{
			Target: nvv1.NvSecurityTarget{
				Selector: nvv1.GroupConfig{
					Name: name,
					Criteria: []nvv1.CriteriaEntry{
						{
							Key:   "service",
							Op:    "=",
							Value: serviceName,
						},
						{
							Key:   "domain",
							Op:    "=",
							Value: namespace,
						},
					},
				},
			},
			ProcessRule: processRules,
			ProcessProfile: &nvv1.NvSecurityProcessProfile{
				Baseline: &baseline,
				Mode:     &mode,
			},
		},
	}
}

func TestNvSecurityRuleToWorkloadPolicy(t *testing.T) {
	tests := []struct {
		name             string
		nvRule           *nvv1.NvSecurityRule
		setupObjects     []runtime.Object
		wantErr          bool
		errContains      string
		wantWorkloadKind string
		wantWorkloadName string
		validatePolicy   func(*testing.T, *nvv1.NvSecurityRule, string)
	}{
		{
			name: "successful conversion with deployment",
			nvRule: newNvSecurityRule(
				"nv.myapp.default",
				"default",
				"myapp.default",
				[]nvv1.NvSecurityProcessRule{
					{
						Name:   "bash",
						Path:   "/bin/bash",
						Action: "allow",
					},
					{
						Name:   "ls",
						Path:   "/bin/ls",
						Action: "allow",
					},
				},
			),
			setupObjects: []runtime.Object{
				newUnstructuredDeployment("myapp", "default", []string{"app-container"}),
			},
			wantErr:          false,
			wantWorkloadKind: "Deployment",
			wantWorkloadName: "myapp",
			validatePolicy: func(t *testing.T, nvRule *nvv1.NvSecurityRule, containerName string) {
				// Additional validation can be done here
			},
		},
		{
			name: "successful conversion with daemonset",
			nvRule: newNvSecurityRule(
				"nv.kube-proxy.kube-system",
				"kube-system",
				"kube-proxy.kube-system",
				[]nvv1.NvSecurityProcessRule{
					{
						Name:   "kube-proxy",
						Path:   "/usr/local/bin/kube-proxy",
						Action: "allow",
					},
				},
			),
			setupObjects: []runtime.Object{
				newUnstructuredDaemonSet("kube-proxy", "kube-system", []string{"kube-proxy"}),
			},
			wantErr:          false,
			wantWorkloadKind: "DaemonSet",
			wantWorkloadName: "kube-proxy",
		},
		{
			name: "invalid security rule - service value matches rule name",
			nvRule: &nvv1.NvSecurityRule{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "nv.myapp.default",
					Namespace: "default",
				},
				Spec: nvv1.NvSecurityRuleSpec{
					Target: nvv1.NvSecurityTarget{
						Selector: nvv1.GroupConfig{
							Name: "nv.myapp.default",
							Criteria: []nvv1.CriteriaEntry{
								{
									Key:   "service",
									Op:    "=",
									Value: "nv.myapp.default",
								},
							},
						},
					},
					ProcessRule: []nvv1.NvSecurityProcessRule{
						{
							Name:   "bash",
							Path:   "/bin/bash",
							Action: "allow",
						},
					},
				},
			},
			setupObjects: []runtime.Object{
				newUnstructuredDeployment("myapp", "default", []string{"app"}),
			},
			wantErr:     true,
			errContains: "no service is defined in criteria",
		},
		{
			name: "invalid security rule - non-allow action",
			nvRule: newNvSecurityRule(
				"nv.myapp.default",
				"default",
				"myapp.default",
				[]nvv1.NvSecurityProcessRule{
					{
						Name:   "bash",
						Path:   "/bin/bash",
						Action: "deny",
					},
				},
			),
			setupObjects: []runtime.Object{
				newUnstructuredDeployment("myapp", "default", []string{"app"}),
			},
			wantErr:     true,
			errContains: "invalid action is detected",
		},
		{
			name: "invalid security rule - non-default process name",
			nvRule: newNvSecurityRule(
				"nv.myapp.default",
				"default",
				"myapp.default",
				[]nvv1.NvSecurityProcessRule{
					{
						Name:   "custom-name",
						Path:   "/bin/bash",
						Action: "allow",
					},
				},
			),
			setupObjects: []runtime.Object{
				newUnstructuredDeployment("myapp", "default", []string{"app"}),
			},
			wantErr:     true,
			errContains: "non-default process name is detected",
		},
		{
			name: "invalid service name - missing nv prefix",
			nvRule: &nvv1.NvSecurityRule{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "myapp.default",
					Namespace: "default",
				},
				Spec: nvv1.NvSecurityRuleSpec{
					Target: nvv1.NvSecurityTarget{
						Selector: nvv1.GroupConfig{
							Name: "myapp.default",
							Criteria: []nvv1.CriteriaEntry{
								{
									Key:   "service",
									Op:    "=",
									Value: "different.default",
								},
							},
						},
					},
					ProcessRule: []nvv1.NvSecurityProcessRule{
						{
							Name:   "bash",
							Path:   "/bin/bash",
							Action: "allow",
						},
					},
				},
			},
			setupObjects: []runtime.Object{
				newUnstructuredDeployment("myapp", "default", []string{"app"}),
			},
			wantErr:     true,
			errContains: "doesn't have 'nv.' prefix",
		},
		{
			name: "workload not found",
			nvRule: newNvSecurityRule(
				"nv.nonexistent.default",
				"default",
				"nonexistent.default",
				[]nvv1.NvSecurityProcessRule{
					{
						Name:   "bash",
						Path:   "/bin/bash",
						Action: "allow",
					},
				},
			),
			setupObjects: []runtime.Object{},
			wantErr:      true,
			errContains:  "no workload found",
		},
		{
			name: "workload with multiple containers",
			nvRule: newNvSecurityRule(
				"nv.myapp.default",
				"default",
				"myapp.default",
				[]nvv1.NvSecurityProcessRule{
					{
						Name:   "bash",
						Path:   "/bin/bash",
						Action: "allow",
					},
				},
			),
			setupObjects: []runtime.Object{
				newUnstructuredDeployment("myapp", "default", []string{"app", "sidecar"}),
			},
			wantErr:     true,
			errContains: "multiple containers",
		},
		{
			name: "successful conversion with statefulset",
			nvRule: newNvSecurityRule(
				"nv.database.production",
				"production",
				"database.production",
				[]nvv1.NvSecurityProcessRule{
					{
						Name:   "postgres",
						Path:   "/usr/bin/postgres",
						Action: "allow",
					},
					{
						Name:   "pg_ctl",
						Path:   "/usr/bin/pg_ctl",
						Action: "allow",
					},
				},
			),
			setupObjects: []runtime.Object{
				newUnstructuredStatefulSet("database", "production", []string{"postgres"}),
			},
			wantErr:          false,
			wantWorkloadKind: "StatefulSet",
			wantWorkloadName: "database",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dynamicClient := dynamicfake.NewSimpleDynamicClient(runtime.NewScheme(), tt.setupObjects...)
			ctx := context.Background()

			policy, workloadKind, workloadName, err := converter.NvSecurityRuleToWorkloadPolicy(
				ctx,
				dynamicClient,
				tt.nvRule,
			)

			if (err != nil) != tt.wantErr {
				t.Errorf("NvSecurityRuleToWorkloadPolicy() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if tt.wantErr && tt.errContains != "" {
				if !strings.Contains(err.Error(), tt.errContains) {
					t.Errorf(
						"NvSecurityRuleToWorkloadPolicy() error = %v, should contain %q",
						err,
						tt.errContains,
					)
				}
				return
			}

			if !tt.wantErr {
				// Validate successful conversion
				if policy == nil {
					t.Error("NvSecurityRuleToWorkloadPolicy() returned nil policy")
					return
				}

				if workloadKind != tt.wantWorkloadKind {
					t.Errorf(
						"NvSecurityRuleToWorkloadPolicy() workloadKind = %v, want %v",
						workloadKind,
						tt.wantWorkloadKind,
					)
				}

				if workloadName != tt.wantWorkloadName {
					t.Errorf(
						"NvSecurityRuleToWorkloadPolicy() workloadName = %v, want %v",
						workloadName,
						tt.wantWorkloadName,
					)
				}

				// Validate policy metadata
				if policy.Name != tt.nvRule.Name {
					t.Errorf(
						"WorkloadPolicy.Name = %v, want %v",
						policy.Name,
						tt.nvRule.Name,
					)
				}

				if policy.Namespace != tt.nvRule.Namespace {
					t.Errorf(
						"WorkloadPolicy.Namespace = %v, want %v",
						policy.Namespace,
						tt.nvRule.Namespace,
					)
				}

				// Validate policy spec
				if policy.Spec.Mode != "monitor" {
					t.Errorf("WorkloadPolicy.Spec.Mode = %v, want 'monitor'", policy.Spec.Mode)
				}

				// Validate rules by container exists
				if len(policy.Spec.RulesByContainer) == 0 {
					t.Error("WorkloadPolicy.Spec.RulesByContainer is empty")
					return
				}

				// Get the container name from the first entry
				var containerName string
				for cn := range policy.Spec.RulesByContainer {
					containerName = cn
					break
				}

				rules := policy.Spec.RulesByContainer[containerName]
				if rules == nil {
					t.Errorf("WorkloadPolicy rules for container %q is nil", containerName)
					return
				}

				// Validate executables match process rules
				if len(rules.Executables.Allowed) != len(tt.nvRule.Spec.ProcessRule) {
					t.Errorf(
						"WorkloadPolicy has %d allowed executables, want %d",
						len(rules.Executables.Allowed),
						len(tt.nvRule.Spec.ProcessRule),
					)
				}

				// Validate each executable path
				for i, processRule := range tt.nvRule.Spec.ProcessRule {
					if i >= len(rules.Executables.Allowed) {
						break
					}
					if rules.Executables.Allowed[i] != processRule.Path {
						t.Errorf(
							"Executable[%d] = %v, want %v",
							i,
							rules.Executables.Allowed[i],
							processRule.Path,
						)
					}
				}

				// Run custom validation if provided
				if tt.validatePolicy != nil {
					tt.validatePolicy(t, tt.nvRule, containerName)
				}
			}
		})
	}
}
