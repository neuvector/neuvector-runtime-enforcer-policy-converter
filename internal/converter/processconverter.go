package converter

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	nvv1 "github.com/neuvector/neuvector/controller/k8sapi/v1"
	securityv1alpha1 "github.com/rancher-sandbox/runtime-enforcer/api/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/apis/meta/internalversion/scheme"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

// NewKubernetesDynamicClient creates a Kubernetes dynamic client using standard kubeconfig resolution.
// It tries in-cluster config first, then falls back to kubeconfig file (~/.kube/config or KUBECONFIG env var).
func NewKubernetesDynamicClient() (dynamic.Interface, error) {
	// Try in-cluster config first (when running inside a pod)
	config, err := rest.InClusterConfig()
	if err != nil {
		// Fall back to kubeconfig file
		loadingRules := clientcmd.NewDefaultClientConfigLoadingRules()
		configOverrides := &clientcmd.ConfigOverrides{}
		kubeConfig := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(
			loadingRules,
			configOverrides,
		)
		config, err = kubeConfig.ClientConfig()
		if err != nil {
			return nil, fmt.Errorf("failed to load kubernetes config: %w", err)
		}
	}

	dynamicClient, err := dynamic.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create kubernetes dynamic client: %w", err)
	}

	return dynamicClient, nil
}

func ReadNvSecurityRules(filepath string) ([]*nvv1.NvSecurityRule, error) {
	var errs error
	var ret []*nvv1.NvSecurityRule

	// TODO: support streaming
	data, err := os.ReadFile(filepath)
	if err != nil {
		return nil, err
	}

	// TODO: support multiple yaml in one file
	decode := scheme.Codecs.UniversalDeserializer().Decode
	err = corev1.AddToScheme(scheme.Scheme)
	if err != nil {
		return nil, err
	}
	err = nvv1.AddToScheme(scheme.Scheme)
	if err != nil {
		return nil, err
	}

	obj, _, err := decode(data, nil, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to decode item: %w", err)
	}

	switch item := obj.(type) {
	// When exporting from NV, it will be a corev1.List.
	case *corev1.List:
		for _, subitem := range item.Items {
			var rawRule runtime.Object
			rawRule, _, err = decode(subitem.Raw, nil, nil)
			if err != nil {
				errs = errors.Join(errs, err)
				continue
			}
			rule, ok := rawRule.(*nvv1.NvSecurityRule)
			if !ok {
				errs = errors.Join(errs, errors.New("failed to parse NvSecurityRule"))
				continue
			}
			ret = append(ret, rule)
		}
	// When used in CRD, it will be an item.
	case *nvv1.NvSecurityRule:
		ret = append(ret, item)
	case *nvv1.NvSecurityRuleList:
		for _, rule := range item.Items {
			ret = append(ret, &rule)
		}
	default:
		errs = errors.Join(errs, fmt.Errorf("invalid object type: %T", item))
	}

	return ret, errs
}

// TODO: handle zero-drift
// TODO: handle deny rules
// TODO: handle non-default services

func ValidateSecurityRule(nvrule *nvv1.NvSecurityRule) error {
	// Verify that it comes with a service criteria.  If not, we can't convert this.
	if !slices.ContainsFunc(nvrule.Spec.Target.Selector.Criteria, func(item nvv1.CriteriaEntry) bool {
		if item.Key == "service" && "nv."+item.Value == nvrule.Name {
			return true
		}
		return false
	}) {
		return errors.New("no service is defined in criteria")
	}

	var reason string
	// Verify if it comes non-allow rule.
	if slices.ContainsFunc(nvrule.Spec.ProcessRule, func(item nvv1.NvSecurityProcessRule) bool {
		if item.Action != "allow" {
			reason = fmt.Sprintf("invalid action is detected: %s", item.Action)
			return true
		}
		if filepath.Base(item.Path) != item.Name {
			reason = fmt.Sprintf("non-default process name is detected: %s", item.Name)
			return true
		}
		return false
	}) {
		return fmt.Errorf("failed to validate security rule: %s", reason)
	}
	return nil
}

func ParseNvServiceName(name string, namespace string) (string, error) {
	if !strings.HasPrefix(name, "nv.") {
		return "", fmt.Errorf("the service name '%s' doesn't have 'nv.' prefix", name)
	}
	if !strings.HasSuffix(name, "."+namespace) {
		return "", fmt.Errorf("the service name '%s' doesn't have '.%s' suffix", name, namespace)
	}
	s := strings.TrimPrefix(name, "nv.")
	s = strings.TrimSuffix(s, "."+namespace)
	s = strings.TrimSpace(s)

	if len(s) == 0 {
		return "", errors.New("empty workload name")
	}
	return s, nil
}

// workloadMatch represents a found workload resource with its container information.
type workloadMatch struct {
	kind          string
	containerName string
	containers    []string // All container names for error reporting
}

// extractContainersFromUnstructured extracts the containers array from an unstructured object.
// Different workload types have containers at different paths:
// - Pod: .spec.containers
// - Deployment/DaemonSet/StatefulSet/ReplicaSet/Job: .spec.template.spec.containers
// - CronJob: .spec.jobTemplate.spec.template.spec.containers.
//
//nolint:goconst // The strings like "Pod" or "containers" are self-explanatory.
func extractContainersFromUnstructured(
	obj *unstructured.Unstructured,
	kind string,
) ([]any, error) {
	var containersPath []string

	switch kind {
	case "Pod":
		containersPath = []string{"spec", "containers"}
	case "Deployment", "DaemonSet", "StatefulSet", "ReplicaSet", "Job":
		containersPath = []string{"spec", "template", "spec", "containers"}
	case "CronJob":
		containersPath = []string{"spec", "jobTemplate", "spec", "template", "spec", "containers"}
	default:
		return nil, fmt.Errorf("unsupported workload kind: %s", kind)
	}

	containers, found, err := unstructured.NestedSlice(obj.Object, containersPath...)
	if err != nil {
		return nil, fmt.Errorf("failed to extract containers from %s: %w", kind, err)
	}
	if !found {
		return nil, fmt.Errorf("containers field not found in %s", kind)
	}

	return containers, nil
}

// validateAndExtractContainer checks that a workload has exactly one container
// and returns a workloadMatch if valid, or an error if not.
func validateAndExtractContainer(
	kind string,
	containersRaw []any,
) (*workloadMatch, error) {
	if len(containersRaw) == 0 {
		return nil, fmt.Errorf("%s has no containers", kind)
	}

	if len(containersRaw) > 1 {
		containerNames := make([]string, len(containersRaw))
		for i, c := range containersRaw {
			containerMap, ok := c.(map[string]any)
			if !ok {
				containerNames[i] = "<unknown>"
				continue
			}
			name, found, err := unstructured.NestedString(containerMap, "name")
			if err != nil || !found {
				containerNames[i] = "<unknown>"
				continue
			}
			containerNames[i] = name
		}
		return nil, fmt.Errorf(
			"%s has multiple containers (%d): %s",
			kind,
			len(containersRaw),
			strings.Join(containerNames, ", "),
		)
	}

	// Extract single container name
	containerMap, ok := containersRaw[0].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("invalid container structure in %s", kind)
	}

	containerName, found, err := unstructured.NestedString(containerMap, "name")
	if err != nil {
		return nil, fmt.Errorf("failed to extract container name from %s: %w", kind, err)
	}
	if !found {
		return nil, fmt.Errorf("container name not found in %s", kind)
	}

	return &workloadMatch{
		kind:          kind,
		containerName: containerName,
		containers:    []string{containerName},
	}, nil
}

// searchWorkloadByGVR searches for a workload resource using dynamic client and GVR.
func searchWorkloadByGVR(
	ctx context.Context,
	dynamicClient dynamic.Interface,
	gvr schema.GroupVersionResource,
	kind string,
	name string,
	namespace string,
) (*workloadMatch, error) {
	obj, err := dynamicClient.Resource(gvr).
		Namespace(namespace).
		Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		return nil, err
	}

	// Extract containers from the unstructured object
	containersRaw, err := extractContainersFromUnstructured(obj, kind)
	if err != nil {
		return nil, err
	}

	// Validate and extract container name
	return validateAndExtractContainer(kind, containersRaw)
}

func NvProcessRulesToWorkloadPolicyRules(nvrules []nvv1.NvSecurityProcessRule) *securityv1alpha1.WorkloadPolicyRules {
	var ret securityv1alpha1.WorkloadPolicyRules
	for _, rule := range nvrules {
		ret.Executables.Allowed = append(ret.Executables.Allowed, rule.Path)
	}
	return &ret
}

type supportedGVR struct {
	gvr  schema.GroupVersionResource
	kind string
}

//nolint:goconst // strings like "apps" are self-explanatory.
func getSupportedGVRs() []supportedGVR {
	return []supportedGVR{
		{
			schema.GroupVersionResource{
				Group:    "apps",
				Version:  "v1",
				Resource: "deployments",
			},
			"Deployment",
		},
		{schema.GroupVersionResource{
			Group:    "apps",
			Version:  "v1",
			Resource: "daemonsets",
		}, "DaemonSet"},
		{schema.GroupVersionResource{
			Group:    "apps",
			Version:  "v1",
			Resource: "statefulsets",
		}, "StatefulSet"},
		{schema.GroupVersionResource{
			Group:    "apps",
			Version:  "v1",
			Resource: "replicasets",
		}, "ReplicaSet"},
		{schema.GroupVersionResource{
			Group:    "batch",
			Version:  "v1",
			Resource: "jobs",
		}, "Job"},
		{schema.GroupVersionResource{
			Group:    "batch",
			Version:  "v1",
			Resource: "cronjobs",
		}, "CronJob"},
		{schema.GroupVersionResource{
			Group:    "",
			Version:  "v1",
			Resource: "pods",
		}, "Pod"},
	}
}

// SearchContainerName searches for a workload resource by name across multiple resource types
// and returns the container name and workload kind if exactly one resource with one container is found.
//
// It searches in this order: Deployment, DaemonSet, StatefulSet, ReplicaSet, Job, CronJob, Pod.
//
// Returns error if:
// - No workload found with the given name
// - Multiple workloads found with the same name (across different types)
// - The found workload has multiple containers.
func SearchContainerName(
	ctx context.Context,
	dynamicClient dynamic.Interface,
	workloadName string,
	namespace string,
) (string, string, error) {
	var matches []workloadMatch

	// Define search configurations (GVR + Kind)
	searchConfigs := getSupportedGVRs()

	// Search all resource types
	for _, config := range searchConfigs {
		match, err := searchWorkloadByGVR(
			ctx,
			dynamicClient,
			config.gvr,
			config.kind,
			workloadName,
			namespace,
		)
		if err != nil {
			// Ignore NotFound errors, return other errors
			if !apierrors.IsNotFound(err) {
				return "", "", fmt.Errorf("error searching %s: %w", config.kind, err)
			}
			continue
		}
		if match != nil {
			matches = append(matches, *match)
		}
	}

	// Validate exactly one resource found
	if len(matches) == 0 {
		return "", "", fmt.Errorf(
			"no workload found with name '%s' in namespace '%s'",
			workloadName,
			namespace,
		)
	}

	if len(matches) > 1 {
		kinds := make([]string, len(matches))
		for i, m := range matches {
			kinds[i] = m.kind
		}
		return "", "", fmt.Errorf(
			"multiple workloads found with name '%s' in namespace '%s': %s",
			workloadName,
			namespace,
			strings.Join(kinds, ", "),
		)
	}

	if matches[0].kind == "Pod" {
		return "", "", fmt.Errorf(
			"runtime-enforcer doesn't support NeuVector service created from pod '%s' in namespace '%s'",
			workloadName,
			namespace,
		)
	}

	match := matches[0]
	return match.containerName, match.kind, nil
}

func NvSecurityRuleToWorkloadPolicy(
	ctx context.Context,
	dynamicClient dynamic.Interface,
	nvrule *nvv1.NvSecurityRule,
) (*securityv1alpha1.WorkloadPolicy, string, string, error) {
	if err := ValidateSecurityRule(nvrule); err != nil {
		return nil, "", "", fmt.Errorf("failed to validate nv security rule: %w", err)
	}

	workloadName, err := ParseNvServiceName(nvrule.Name, nvrule.Namespace)
	if err != nil {
		return nil, "", "", fmt.Errorf("failed to parse service name: %w", err)
	}

	containerName, workloadKind, err := SearchContainerName(ctx, dynamicClient, workloadName, nvrule.Namespace)
	if err != nil {
		return nil, "", "", fmt.Errorf("failed to search container name: %w", err)
	}

	ret := &securityv1alpha1.WorkloadPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      nvrule.Name,
			Namespace: nvrule.Namespace,
		},
		Spec: securityv1alpha1.WorkloadPolicySpec{
			Mode: "monitor", // TODO: export this to securityv1alpha1
			RulesByContainer: map[string]*securityv1alpha1.WorkloadPolicyRules{
				containerName: NvProcessRulesToWorkloadPolicyRules(nvrule.Spec.ProcessRule),
			},
		},
		Status: securityv1alpha1.WorkloadPolicyStatus{},
	}
	return ret, workloadKind, workloadName, nil
}
