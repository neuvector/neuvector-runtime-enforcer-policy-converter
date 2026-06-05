package converter

import (
	"fmt"
	"io"

	securityv1alpha1 "github.com/rancher-sandbox/runtime-enforcer/api/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/apis/meta/internalversion/scheme"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer/json"
)

// WriteWorkloadPoliciesToYAML serializes a slice of WorkloadPolicy objects to YAML format.
// The output is a Kubernetes List containing all policies, compatible with kubectl apply.
func WriteWorkloadPoliciesToYAML(policies []*securityv1alpha1.WorkloadPolicy, writer io.Writer) error {
	// Register required schemes
	err := corev1.AddToScheme(scheme.Scheme)
	if err != nil {
		return fmt.Errorf("failed to add corev1 scheme: %w", err)
	}
	err = securityv1alpha1.AddToScheme(scheme.Scheme)
	if err != nil {
		return fmt.Errorf("failed to add securityv1alpha1 scheme: %w", err)
	}

	// Create a Kubernetes List to hold all policies
	list := &corev1.List{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "v1",
			Kind:       "List",
		},
		Items: make([]runtime.RawExtension, 0, len(policies)),
	}

	// Convert each policy to RawExtension and add to list
	for _, policy := range policies {
		// Ensure TypeMeta is set
		policy.TypeMeta = metav1.TypeMeta{
			APIVersion: "security.rancher-sandbox.io/v1alpha1",
			Kind:       "WorkloadPolicy",
		}

		list.Items = append(list.Items, runtime.RawExtension{Object: policy})
	}

	// Serialize the List to YAML
	serializer := json.NewSerializerWithOptions(
		json.DefaultMetaFactory,
		scheme.Scheme,
		scheme.Scheme,
		json.SerializerOptions{Yaml: true, Pretty: true, Strict: false},
	)

	err = serializer.Encode(list, writer)
	if err != nil {
		return fmt.Errorf("failed to encode list: %w", err)
	}

	return nil
}
