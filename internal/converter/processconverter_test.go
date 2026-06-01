package converter_test

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/neuvector/neuvector-runtime-enforcer-policy-converter/internal/converter"
	nvv1 "github.com/neuvector/neuvector/controller/k8sapi/v1"
	securityv1alpha1 "github.com/rancher-sandbox/runtime-enforcer/api/v1alpha1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/apis/meta/internalversion/scheme"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	dynamicfake "k8s.io/client-go/dynamic/fake"
)

func TestMain(m *testing.M) {
	var err error
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))

	err = appsv1.AddToScheme(scheme.Scheme)
	if err != nil {
		logger.Error("failed to add appsv1 scheme", "error", err)
		os.Exit(-1)
	}
	err = corev1.AddToScheme(scheme.Scheme)
	if err != nil {
		logger.Error("failed to add corev1 scheme", "error", err)
		os.Exit(-1)
	}
	err = batchv1.AddToScheme(scheme.Scheme)
	if err != nil {
		logger.Error("failed to add batchv1 scheme", "error", err)
		os.Exit(-1)
	}
	err = nvv1.AddToScheme(scheme.Scheme)
	if err != nil {
		logger.Error("failed to add batchv1 scheme", "error", err)
		os.Exit(-1)
	}

	os.Exit(m.Run())
}

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

func readObjectYaml(t *testing.T, filepath string, mutate func(runtime.Object)) runtime.Object {
	t.Helper()
	decode := serializer.NewCodecFactory(scheme.Scheme).UniversalDeserializer().Decode

	content, err := os.ReadFile(filepath)
	require.NoError(t, err)

	obj, _, err := decode(content, nil, nil)
	require.NoError(t, err)

	if mutate != nil {
		mutate(obj)
	}

	return obj
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
			workloadName: "opensuse-deployment",
			namespace:    "default",
			setupObjects: []runtime.Object{
				readObjectYaml(t, "./testdata/workloads/opensuse-deployment.yaml", nil),
			},
			wantContainer: "opensuse",
			wantKind:      "Deployment",
			wantErr:       false,
		},
		{
			name:         "daemonset with single container",
			workloadName: "opensuse-daemonset",
			namespace:    "kube-system",
			setupObjects: []runtime.Object{
				readObjectYaml(t, "./testdata/workloads/opensuse-daemonset.yaml", nil),
			},
			wantContainer: "opensuse",
			wantKind:      "DaemonSet",
			wantErr:       false,
		},
		{
			name:         "statefulset with single container",
			workloadName: "opensuse-statefulset",
			namespace:    "default",
			setupObjects: []runtime.Object{
				readObjectYaml(t, "./testdata/workloads/opensuse-statefulset.yaml", nil),
			},
			wantContainer: "app",
			wantKind:      "StatefulSet",
			wantErr:       false,
		},
		{
			name:         "replicaset with single container",
			workloadName: "opensuse-replicaset",
			namespace:    "default",
			setupObjects: []runtime.Object{
				readObjectYaml(t, "./testdata/workloads/opensuse-replicaset.yaml", nil),
			},
			wantContainer: "app",
			wantKind:      "ReplicaSet",
			wantErr:       false,
		},
		{
			name:         "job with single container",
			workloadName: "opensuse-job",
			namespace:    "default",
			setupObjects: []runtime.Object{
				readObjectYaml(t, "./testdata/workloads/opensuse-job.yaml", nil),
			},
			wantContainer: "job",
			wantKind:      "Job",
			wantErr:       false,
		},
		{
			name:         "cronjob with single container",
			workloadName: "opensuse-cronjob",
			namespace:    "default",
			setupObjects: []runtime.Object{
				readObjectYaml(t, "./testdata/workloads/opensuse-cronjob.yaml", nil),
			},
			wantContainer: "opensuse",
			wantKind:      "CronJob",
			wantErr:       false,
		},
		{
			name:         "pod with single container",
			workloadName: "opensuse-pod",
			namespace:    "default",
			setupObjects: []runtime.Object{
				readObjectYaml(t, "./testdata/workloads/opensuse-pod.yaml", nil),
			},
			wantContainer: "app",
			wantKind:      "Pod",
			wantErr:       true, // TODO: this should fail
			errContains:   "runtime-enforcer doesn't support NeuVector service created from pod",
		},
		{
			name:         "deployment with multiple containers",
			workloadName: "opensuse-deployment",
			namespace:    "default",
			setupObjects: []runtime.Object{
				readObjectYaml(t, "./testdata/workloads/opensuse-deployment.yaml", func(o runtime.Object) {
					deployment := o.(*appsv1.Deployment)
					deployment.Spec.Template.Spec.Containers = append(
						deployment.Spec.Template.Spec.Containers,
						corev1.Container{
							Name:  "sidecar",
							Image: "registry.opensuse.org/opensuse/bci/bci-ci:3",
						},
					)
				}),
			},
			wantErr:     true,
			errContains: "multiple containers",
		},
		{
			name:         "multiple workload types with same name",
			workloadName: "myapp",
			namespace:    "default",
			setupObjects: []runtime.Object{
				readObjectYaml(t, "./testdata/workloads/opensuse-deployment.yaml", func(o runtime.Object) {
					deployment := o.(*appsv1.Deployment)
					deployment.ObjectMeta.Name = "myapp"
				}),
				readObjectYaml(t, "./testdata/workloads/opensuse-pod.yaml", func(o runtime.Object) {
					pod := o.(*corev1.Pod)
					pod.ObjectMeta.Name = "myapp"
				}),
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
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dynamicClient := dynamicfake.NewSimpleDynamicClient(scheme.Scheme, tt.setupObjects...)
			ctx := context.Background()

			gotContainer, gotKind, err := converter.SearchContainerName(
				ctx,
				dynamicClient,
				tt.workloadName,
				tt.namespace,
			)

			if tt.wantErr {
				require.Error(t, err)
				require.Contains(t, err.Error(), tt.errContains)
			} else {
				require.NoError(t, err)
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

// newNvSecurityRule creates a test NvSecurityRule with the given parameters.
func newNvSecurityRule(
	name, namespace, serviceName string,
	processRules []nvv1.NvSecurityProcessRule,
) *nvv1.NvSecurityRule {
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

// TODO: verify workload name/types

func validatePolicy(t *testing.T, nvRule *nvv1.NvSecurityRule, wp *securityv1alpha1.WorkloadPolicy) {
	// The two CRDs should have the same name and namespaces.
	assert.Equal(t, nvRule.Name, wp.Name)
	assert.Equal(t, nvRule.Namespace, wp.Namespace)

	// The WorkloadPolicy should contain on container only.
	assert.Len(t, wp.Spec.RulesByContainer, 1)

	// Verify that all allow policies exist in the new WP CR.
	for _, ruleByContainer := range wp.Spec.RulesByContainer {
		for _, rule := range ruleByContainer.Executables.Allowed {
			assert.True(t, slices.ContainsFunc(nvRule.Spec.ProcessRule, func(r nvv1.NvSecurityProcessRule) bool {
				if r.Action == "allow" && r.Path == rule {
					return true
				}
				return false
			}))
		}
	}
}

func TestNvSecurityRuleToWorkloadPolicy(t *testing.T) {
	tests := []struct {
		name             string
		nvRule           runtime.Object
		setupObjects     []runtime.Object
		wantErr          bool
		errContains      string
		wantWorkloadKind string
		wantWorkloadName string
		validatePolicy   func(*testing.T, *nvv1.NvSecurityRule, *securityv1alpha1.WorkloadPolicy)
	}{
		{
			name:   "successful conversion with deployment",
			nvRule: readObjectYaml(t, "./testdata/opensuse-deployment.yaml", nil),
			setupObjects: []runtime.Object{
				readObjectYaml(t, "./testdata/workloads/opensuse-deployment.yaml", nil),
			},
			wantErr:          false,
			wantWorkloadKind: "Deployment",
			wantWorkloadName: "opensuse-deployment",
			validatePolicy:   validatePolicy,
		},
		{
			name: "invalid security rule - service value should match rule name",
			nvRule: readObjectYaml(t, "./testdata/opensuse-deployment.yaml", func(o runtime.Object) {
				rule := o.(*nvv1.NvSecurityRule)
				rule.Spec.Target.Selector.Criteria = []nvv1.CriteriaEntry{
					{
						Key:   "service",
						Op:    "=",
						Value: "invalid path",
					},
				}
			}),
			setupObjects: []runtime.Object{
				readObjectYaml(t, "./testdata/workloads/opensuse-deployment.yaml", nil),
			},
			wantErr:     true,
			errContains: "no service is defined in criteria",
		},
		/*
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
		*/
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dynamicClient := dynamicfake.NewSimpleDynamicClient(runtime.NewScheme(), tt.setupObjects...)
			ctx := context.Background()

			policy, workloadKind, workloadName, err := converter.NvSecurityRuleToWorkloadPolicy(
				ctx,
				dynamicClient,
				tt.nvRule.(*nvv1.NvSecurityRule),
			)

			if tt.wantErr {
				require.Error(t, err)
				require.Contains(t, err.Error(), tt.errContains)
			} else {
				require.NoError(t, err)
				require.Equal(t, tt.wantWorkloadKind, workloadKind)
				require.Equal(t, tt.wantWorkloadName, workloadName)
				// Run custom validation if provided
				if tt.validatePolicy != nil {
					tt.validatePolicy(t, tt.nvRule.(*nvv1.NvSecurityRule), policy)
				}
			}
		})
	}
}
