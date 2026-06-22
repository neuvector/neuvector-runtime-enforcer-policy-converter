//go:build e2e

package e2e_test

import (
	"os"
	"testing"

	"sigs.k8s.io/e2e-framework/pkg/env"
	"sigs.k8s.io/e2e-framework/pkg/envconf"
	"sigs.k8s.io/e2e-framework/pkg/envfuncs"
	"sigs.k8s.io/e2e-framework/support/kind"
)

//nolint:gochecknoglobals
var (
	testEnv      env.Environment
	converterBin = "../../bin/converter"
)

const e2ePrefix = "nv-converter-e2e"

func TestMain(m *testing.M) {
	cfg, _ := envconf.NewFromFlags()
	testEnv = env.NewWithConfig(cfg)
	clusterName := envconf.RandomName(e2ePrefix, 32)

	testEnv.Setup(
		envfuncs.CreateCluster(kind.NewProvider(), clusterName),
	)
	testEnv.Finish(
		envfuncs.ExportClusterLogs(clusterName, "./logs"),
		envfuncs.DestroyCluster(clusterName),
	)
	os.Exit(testEnv.Run(m))
}
