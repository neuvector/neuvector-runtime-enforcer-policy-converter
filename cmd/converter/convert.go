package main

import (
	"context"
	"errors"
	"fmt"
	"os"

	"github.com/neuvector/neuvector-runtime-enforcer-policy-converter/internal/converter"
	v1 "github.com/neuvector/neuvector/controller/k8sapi/v1"
	"github.com/rancher-sandbox/runtime-enforcer/api/v1alpha1"
	"github.com/urfave/cli/v3"
	"k8s.io/client-go/dynamic"
)

func convertAction(ctx context.Context, c *cli.Command) error {
	var err error
	var dynamicClient dynamic.Interface
	var rules []*v1.NvSecurityRule

	// Validate that we have at least one input file
	if c.Args().Len() == 0 {
		return errors.New("no input files provided")
	}

	// Get and validate mode flag
	mode := c.String("mode")
	if mode != v1alpha1.PolicyModeMonitor && mode != v1alpha1.PolicyModeProtect {
		return fmt.Errorf("invalid mode %q: must be 'monitor' or 'protect'", mode)
	}

	// Get output flag
	output := c.String("output")

	// Create Kubernetes dynamic client
	dynamicClient, err = converter.NewKubernetesDynamicClient()
	if err != nil {
		return fmt.Errorf("failed to create Kubernetes client: %w", err)
	}

	// Get all input file paths
	filepaths := c.Args().Slice()

	// Convert each rule to WorkloadPolicy
	var policies []*v1alpha1.WorkloadPolicy
	var conversionWarnings []converter.Warning
	var conversionErrors []error

	for _, filepath := range filepaths {
		// Read all NvSecurityRules from input files
		rules, err = converter.ReadNvSecurityRules([]string{filepath}) // TODO: change the prototype to string
		if err != nil {
			conversionErrors = append(
				conversionErrors,
				err,
			)
			continue
		}

		if len(rules) == 0 {
			conversionErrors = append(
				conversionErrors,
				fmt.Errorf("%s: no NvSecurityRule resources are found", filepath),
			)
			continue
		}

		for _, rule := range rules {
			policy, _, _, warns, errs := converter.NvSecurityRuleToWorkloadPolicy(ctx, dynamicClient, rule, mode)
			if errs != nil {
				conversionErrors = append(
					conversionErrors,
					fmt.Errorf("%s: failed to convert rule %s/%s: %w", filepath, rule.Namespace, rule.Name, errs),
				)
				continue
			}
			for _, warning := range warns {
				conversionWarnings = append(conversionWarnings, fmt.Errorf("%s: %w", filepath, warning))
			}
			policies = append(policies, policy)
		}
	}

	// Report warnings
	for _, warning := range conversionWarnings {
		fmt.Fprintf(os.Stderr, "WARNING: %v\n", warning)
	}
	for _, convertErr := range conversionErrors {
		fmt.Fprintf(os.Stderr, "ERROR: %v\n", convertErr)
	}

	// Check if we have any successfully converted policies
	if len(policies) == 0 {
		return errors.New("no rule is converted")
	}

	// Determine output writer
	var writer *os.File
	if output == "-" {
		writer = os.Stdout
	} else {
		var out *os.File
		// Create output file
		out, err = os.Create(output)
		if err != nil {
			return fmt.Errorf("failed to create output file %s: %w", output, err)
		}
		defer out.Close()
		writer = out
	}

	// Write WorkloadPolicies to YAML
	err = converter.WriteWorkloadPoliciesToYAML(policies, writer)
	if err != nil {
		return fmt.Errorf("failed to write YAML output: %w", err)
	}

	// Print summary to stderr (so stdout stays clean for YAML output)
	fmt.Fprintf(os.Stderr, "\nConversion summary:\n")
	fmt.Fprintf(os.Stderr, "  Input files: %d\n", len(filepaths))
	fmt.Fprintf(os.Stderr, "  Rules read: %d\n", len(rules))
	fmt.Fprintf(os.Stderr, "  Policies converted: %d\n", len(policies))
	if output != "-" {
		fmt.Fprintf(os.Stderr, "  Output written to: %s\n", output)
	}

	return nil
}
