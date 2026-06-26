package converter

import (
	"fmt"
	"io"

	securityv1alpha1 "github.com/rancher-sandbox/runtime-enforcer/api/v1alpha1"
	"k8s.io/apimachinery/pkg/apis/meta/internalversion/scheme"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/serializer/json"
)

// WriteWorkloadPoliciesToYAML serializes a slice of WorkloadPolicy objects to YAML format.
// Policies are separated by "---" delimiters, compatible with kubectl apply -f.
func WriteWorkloadPoliciesToYAML(policies []*securityv1alpha1.WorkloadPolicy, writer io.Writer) error {
	// Register required schemes
	err := securityv1alpha1.AddToScheme(scheme.Scheme)
	if err != nil {
		return fmt.Errorf("failed to add securityv1alpha1 scheme: %w", err)
	}

	// Create YAML serializer
	serializer := json.NewSerializerWithOptions(
		json.DefaultMetaFactory,
		scheme.Scheme,
		scheme.Scheme,
		json.SerializerOptions{Yaml: true, Pretty: true, Strict: false},
	)

	// Serialize each policy with "---" separator
	for i, policy := range policies {
		// Ensure TypeMeta is set
		policy.TypeMeta = metav1.TypeMeta{
			APIVersion: securityv1alpha1.GroupVersion.String(),
			Kind:       "WorkloadPolicy",
		}

		// Add separator between documents (not before the first one)
		if i > 0 {
			if _, err = writer.Write([]byte("---\n")); err != nil {
				return fmt.Errorf("failed to write document separator: %w", err)
			}
		}

		// Serialize the policy
		if err = serializer.Encode(policy, writer); err != nil {
			return fmt.Errorf("failed to encode policy %s/%s: %w", policy.Namespace, policy.Name, err)
		}
	}

	return nil
}
