// Copyright Istio Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package analyze

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/yaml"

	"istio.io/istio/istioctl/pkg/cli"
	"istio.io/istio/istioctl/pkg/util/testutil"
	"istio.io/istio/pkg/cluster"
	"istio.io/istio/pkg/config/analysis/diag"
	"istio.io/istio/pkg/kube"
	"istio.io/istio/pkg/kube/multicluster"
)

func TestErrorOnIssuesFound(t *testing.T) {
	g := NewWithT(t)

	msgs := []diag.Message{
		diag.NewMessage(
			diag.NewMessageType(diag.Error, "B1", "Template: %q"),
			nil,
			"",
		),
		diag.NewMessage(
			diag.NewMessageType(diag.Warning, "A1", "Template: %q"),
			nil,
			"",
		),
	}

	err := errorIfMessagesExceedThreshold(msgs)

	g.Expect(err).To(BeIdenticalTo(AnalyzerFoundIssuesError{}))
}

func TestNoErrorIfMessageLevelsBelowThreshold(t *testing.T) {
	g := NewWithT(t)

	msgs := []diag.Message{
		diag.NewMessage(
			diag.NewMessageType(diag.Info, "B1", "Template: %q"),
			nil,
			"",
		),
		diag.NewMessage(
			diag.NewMessageType(diag.Warning, "A1", "Template: %q"),
			nil,
			"",
		),
	}

	err := errorIfMessagesExceedThreshold(msgs)

	g.Expect(err).To(BeNil())
}

func TestSkipPodsInFiles(t *testing.T) {
	c := testutil.TestCase{
		Args: strings.Split(
			"-A --use-kube=false --failure-threshold ERROR testdata/analyze-file/public-gateway.yaml",
			" "),
		WantException: false,
	}
	analyze := Analyze(cli.NewFakeContext(nil))
	testutil.VerifyOutput(t, analyze, c)
}

func TestAnalyzeReturnsMeshConfigFileError(t *testing.T) {
	meshConfigPath := filepath.Join(t.TempDir(), "mesh-config.yaml")
	invalidMeshConfig := `extensionProviders:
- name: ext-authz
  envoyExtAuthzGrpc:
    service: ext-authz.example.svc.cluster.local
    port: 9000
    statusOnError: 503
`
	if err := os.WriteFile(meshConfigPath, []byte(invalidMeshConfig), 0o600); err != nil {
		t.Fatal(err)
	}

	analyze := Analyze(cli.NewFakeContext(nil))
	analyze.SetArgs([]string{"--use-kube=false", "--meshConfigFile", meshConfigPath})
	analyze.SilenceUsage = true

	err := analyze.Execute()
	if err == nil {
		t.Fatal("expected invalid mesh config file to return an error")
	}
	if !strings.Contains(err.Error(), "failed to load mesh config file") {
		t.Fatalf("expected mesh config file error, got %v", err)
	}
}

func TestGetClientsRejectsUnsafeMultiClusterSecret(t *testing.T) {
	g := NewWithT(t)

	maliciousKubeconfig := []byte(`
apiVersion: v1
kind: Config
clusters:
- name: remote
  cluster:
    server: https://remote.example.com
contexts:
- name: remote-context
  context:
    cluster: remote
    user: attacker
current-context: remote-context
users:
- name: attacker
  user:
    exec:
      apiVersion: client.authentication.k8s.io/v1
      command: /bin/sh
      args: ["-c", "touch /tmp/pwned-by-istioctl"]
      interactiveMode: Never
`)

	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "remote-cluster-secret",
			Namespace: "istio-system",
			Labels: map[string]string{
				multicluster.MultiClusterSecretLabel: "true",
			},
		},
		Data: map[string][]byte{
			"remote-cluster": maliciousKubeconfig,
		},
	}

	ctx := cli.NewFakeContext(&cli.NewFakeContextOption{
		IstioNamespace: "istio-system",
		Objects:        []runtime.Object{secret},
	})

	_, err := getClients(ctx)

	g.Expect(err).To(HaveOccurred())
	g.Expect(err.Error()).To(ContainSubstring("exec is not allowed"))
}

func TestGetClientsAllowsLegitimateTokenSecret(t *testing.T) {
	g := NewWithT(t)

	oldRevision := revisionSpecified
	revisionSpecified = "canary"
	t.Cleanup(func() { revisionSpecified = oldRevision })

	legitKubeconfig := []byte(`
apiVersion: v1
kind: Config
clusters:
- name: remote
  cluster:
    server: https://127.0.0.1:6443
    insecure-skip-tls-verify: true
contexts:
- name: remote-context
  context:
    cluster: remote
    user: remote-sa
current-context: remote-context
users:
- name: remote-sa
  user:
    token: some-bearer-token
`)

	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "remote-cluster-secret",
			Namespace: "istio-system",
			Labels: map[string]string{
				multicluster.MultiClusterSecretLabel: "true",
			},
		},
		Data: map[string][]byte{
			"remote-cluster": legitKubeconfig,
		},
	}

	ctx := cli.NewFakeContext(&cli.NewFakeContextOption{
		IstioNamespace: "istio-system",
		Objects:        []runtime.Object{secret},
	})

	clients, err := getClients(ctx)

	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(clients).To(HaveLen(2)) // local fake client + the sanitized remote one

	remote := clients[1]
	g.Expect(remote.remote).To(BeTrue())
	g.Expect(remote.client.ClusterID()).To(Equal(cluster.ID("remote")))

	cliClient, ok := remote.client.(kube.CLIClient)
	g.Expect(ok).To(BeTrue())
	g.Expect(cliClient.Revision()).To(Equal("canary"))
}

func TestRunSpecificAnalyzer(t *testing.T) {
	ctx := cli.NewFakeContext(&cli.NewFakeContextOption{
		IstioNamespace: "istio-system",
	})

	cases := []struct {
		caseName string
		testutil.TestCase
	}{
		{
			caseName: "failed-with-all-analyzers",
			TestCase: testutil.TestCase{
				Args: strings.Split(
					"--use-kube=false testdata/analyze-file/specific-analyzer.yaml",
					" "),
				WantException: true,
			},
		},
		{
			caseName: "failed-with-specific-analyzer",
			TestCase: testutil.TestCase{
				Args: strings.Split(
					"--use-kube=false --analyzer schema.ValidationAnalyzer.Gateway testdata/analyze-file/specific-analyzer.yaml",
					" "),
				WantException: true,
			},
		},
		{
			caseName: "passed-with-specific-analyzer",
			TestCase: testutil.TestCase{
				Args: strings.Split(
					"--use-kube=false --analyzer gateway.ConflictingGatewayAnalyzer testdata/analyze-file/specific-analyzer.yaml",
					" "),
				WantException: false,
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.caseName, func(t *testing.T) {
			analyze := Analyze(ctx)
			testutil.VerifyOutput(t, analyze, tc.TestCase)
		})
	}
}

// brokenGatewaysYaml is a file-only analysis input that reports two IST0106
// schema validation errors on named Gateway resources (alpha and beta).
const brokenGatewaysYaml = `apiVersion: networking.istio.io/v1
kind: Gateway
metadata:
  name: beta
spec:
  selector:
    istio: ingressgateway
  servers:
    - hosts:
        - "foo.bar"
---
apiVersion: networking.istio.io/v1
kind: Gateway
metadata:
  name: alpha
spec:
  selector:
    istio: ingressgateway
  servers:
    - hosts:
        - "bar.bar"
`

// partiallyFixedGatewaysYaml fixes alpha but introduces a new broken gateway
// (gamma): relative to a baseline of brokenGatewaysYaml this yields one new,
// one known and one disappeared diagnostic.
const partiallyFixedGatewaysYaml = `apiVersion: networking.istio.io/v1
kind: Gateway
metadata:
  name: beta
spec:
  selector:
    istio: ingressgateway
  servers:
    - hosts:
        - "foo.bar"
---
apiVersion: networking.istio.io/v1
kind: Gateway
metadata:
  name: alpha
spec:
  selector:
    istio: ingressgateway
  servers:
    - port:
        number: 80
        name: http
        protocol: HTTP
      hosts:
        - "bar.bar"
---
apiVersion: networking.istio.io/v1
kind: Gateway
metadata:
  name: gamma
spec:
  selector:
    istio: ingressgateway
  servers:
    - hosts:
        - "gamma.baz"
`

func runAnalyze(t *testing.T, args ...string) (string, error) {
	t.Helper()
	cmd := Analyze(cli.NewFakeContext(nil))
	cmd.SetArgs(args)
	cmd.SilenceUsage = true
	var out strings.Builder
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	err := cmd.Execute()
	return out.String(), err
}

// tempDir creates a best-effort temporary directory. The file analyzer keeps
// input files open until a finalizer runs, so removal can fail on Windows;
// cleanup errors are therefore intentionally ignored.
func tempDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "istioctl-analyze-test-*")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}

func exportBaselineFor(t *testing.T, inputFile string) string {
	t.Helper()
	baselinePath := filepath.Join(tempDir(t), "baseline.yaml")
	out, err := runAnalyze(t, "--use-kube=false", "--failure-threshold", "ERROR",
		"--baseline-export", baselinePath, inputFile)
	if err != nil {
		t.Fatalf("baseline export failed: %v\noutput: %s", err, out)
	}
	data, err := os.ReadFile(baselinePath)
	if err != nil {
		t.Fatalf("baseline file was not written: %v", err)
	}
	if !strings.Contains(string(data), "version: v1alpha1") {
		t.Fatalf("exported baseline missing version:\n%s", string(data))
	}
	return baselinePath
}

func writeTempYAML(t *testing.T, name, content string) string {
	t.Helper()
	path := filepath.Join(tempDir(t), name)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestBaselineExportAndAccept(t *testing.T) {
	input := writeTempYAML(t, "gateways.yaml", brokenGatewaysYaml)
	baselinePath := exportBaselineFor(t, input)

	// Without a baseline the same diagnostics fail the command.
	out, err := runAnalyze(t, "--use-kube=false", "--failure-threshold", "ERROR", input)
	if err == nil {
		t.Fatalf("expected analysis without baseline to fail, got output: %s", out)
	}

	// With the exported baseline the identical diagnostics are accepted.
	out, err = runAnalyze(t, "--use-kube=false", "--failure-threshold", "ERROR",
		"--baseline", baselinePath, input)
	if err != nil {
		t.Fatalf("expected baseline to accept identical diagnostics, got err: %v\noutput: %s", err, out)
	}
	if !strings.Contains(out, "Known diagnostics") || !strings.Contains(out, "0 new, 2 known") {
		t.Fatalf("expected known diagnostics and summary, got: %s", out)
	}
}

func TestBaselineIgnoresLineNumbersAndOrder(t *testing.T) {
	input := writeTempYAML(t, "gateways.yaml", brokenGatewaysYaml)
	baselinePath := exportBaselineFor(t, input)

	// Shift every diagnostic to a different line number: matching must be unaffected.
	shifted := writeTempYAML(t, "shifted.yaml", "\n\n# padding line\n"+brokenGatewaysYaml)
	out, err := runAnalyze(t, "--use-kube=false", "--failure-threshold", "ERROR",
		"--baseline", baselinePath, shifted)
	if err != nil {
		t.Fatalf("expected line number shifts not to break baseline matching: %v\noutput: %s", err, out)
	}
	if !strings.Contains(out, "0 new, 2 known, 0 disappeared, 0 expired") {
		t.Fatalf("expected all diagnostics to remain known, got: %s", out)
	}
}

func TestBaselineNewIssueFailsAndFixedIssueDisappears(t *testing.T) {
	input := writeTempYAML(t, "gateways.yaml", brokenGatewaysYaml)
	baselinePath := exportBaselineFor(t, input)
	changed := writeTempYAML(t, "changed.yaml", partiallyFixedGatewaysYaml)

	out, err := runAnalyze(t, "--use-kube=false", "--failure-threshold", "ERROR",
		"--baseline", baselinePath, changed)
	if err == nil {
		t.Fatalf("expected the new diagnostic to fail the command, output: %s", out)
	}
	for _, want := range []string{
		"1 new, 1 known, 1 disappeared, 0 expired",
		"Gateway default/gamma",
		"Disappeared baseline entries",
		"Gateway default/alpha",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("expected output to contain %q, got: %s", want, out)
		}
	}
}

func TestBaselineExpiredEntryResurfaces(t *testing.T) {
	input := writeTempYAML(t, "gateways.yaml", brokenGatewaysYaml)
	baselinePath := exportBaselineFor(t, input)

	// Mark the first exported entry as expired in 2020; leave the other one valid.
	raw, err := os.ReadFile(baselinePath)
	if err != nil {
		t.Fatal(err)
	}
	doc := map[string]any{}
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	entries := doc["entries"].([]any)
	first := entries[0].(map[string]any)
	first["expiresAt"] = "2020-01-01T00:00:00Z"
	rewritten, err := yaml.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(baselinePath, rewritten, 0o600); err != nil {
		t.Fatal(err)
	}

	out, err := runAnalyze(t, "--use-kube=false", "--failure-threshold", "ERROR",
		"--baseline", baselinePath, input)
	if err == nil {
		t.Fatalf("expected expired diagnostic to fail the command again, output: %s", out)
	}
	if !strings.Contains(out, "1 new, 1 known, 0 disappeared, 1 expired") {
		t.Fatalf("expected one expired entry, got: %s", out)
	}
	if !strings.Contains(out, "Expired baseline entries") {
		t.Fatalf("expected expired entries to be summarized, got: %s", out)
	}
}

func TestBaselineMalformedFileFailsClearly(t *testing.T) {
	input := writeTempYAML(t, "gateways.yaml", brokenGatewaysYaml)

	cases := map[string]string{
		"missing file":     filepath.Join(t.TempDir(), "does-not-exist.yaml"),
		"syntax error":     writeTempYAML(t, "bad-syntax.yaml", "version: v1alpha1\nentries: [\n"),
		"bad version":      writeTempYAML(t, "bad-version.yaml", "version: v9\nentries: []\n"),
		"missing level":    writeTempYAML(t, "bad-level.yaml", "version: v1alpha1\nentries:\n- code: IST0106\n  resource: Gateway default/alpha\n"),
		"missing resource": writeTempYAML(t, "bad-resource.yaml", "version: v1alpha1\nentries:\n- code: IST0106\n  level: Error\n"),
		"invalid expiry":   writeTempYAML(t, "bad-expiry.yaml", "version: v1alpha1\nentries:\n- code: IST0106\n  level: Error\n  resource: Gateway default/alpha\n  expiresAt: tomorrow\n"),
	}
	for name, path := range cases {
		t.Run(name, func(t *testing.T) {
			out, err := runAnalyze(t, "--use-kube=false", "--baseline", path, input)
			if err == nil {
				t.Fatalf("expected %s baseline to fail, output: %s", name, out)
			}
			if !strings.Contains(err.Error(), "baseline") {
				t.Fatalf("expected a clear baseline error for %s, got: %v", name, err)
			}
		})
	}
}

func TestBaselineFlagsAreMutuallyExclusive(t *testing.T) {
	input := writeTempYAML(t, "gateways.yaml", brokenGatewaysYaml)
	baselinePath := filepath.Join(t.TempDir(), "baseline.yaml")
	_, err := runAnalyze(t, "--use-kube=false",
		"--baseline", baselinePath, "--baseline-export", baselinePath+".new", input)
	if err == nil || !strings.Contains(err.Error(), "cannot be used at the same time") {
		t.Fatalf("expected a mutually-exclusive flags error, got: %v", err)
	}
}

func TestBaselineJSONOutput(t *testing.T) {
	input := writeTempYAML(t, "gateways.yaml", brokenGatewaysYaml)
	baselinePath := exportBaselineFor(t, input)

	out, err := runAnalyze(t, "--use-kube=false", "-o", "json", "--baseline", baselinePath, input)
	if err != nil {
		t.Fatalf("unexpected error: %v\noutput: %s", err, out)
	}
	// stdout (the JSON document) and stderr (the baseline summary) share one
	// buffer, so extract the JSON object before decoding.
	start, end := strings.Index(out, "{"), strings.LastIndex(out, "}")
	if start < 0 || end < start {
		t.Fatalf("no JSON document found in output: %s", out)
	}
	var parsed struct {
		Messages []struct {
			Code           string `json:"code"`
			BaselineStatus string `json:"baselineStatus"`
		} `json:"messages"`
		BaselineReport struct {
			New         int `json:"new"`
			Known       []map[string]any
			Disappeared []map[string]any
			Expired     []map[string]any
		} `json:"baselineReport"`
	}
	if err := json.Unmarshal([]byte(out[start:end+1]), &parsed); err != nil {
		t.Fatalf("invalid JSON output: %v\n%s", err, out)
	}
	if len(parsed.Messages) != 2 {
		t.Fatalf("expected 2 messages, got %d", len(parsed.Messages))
	}
	for _, m := range parsed.Messages {
		if m.BaselineStatus != "known" || m.Code != "IST0106" {
			t.Fatalf("expected known IST0106 message, got %+v", m)
		}
	}
	if parsed.BaselineReport.New != 0 || len(parsed.BaselineReport.Known) != 2 ||
		len(parsed.BaselineReport.Disappeared) != 0 || len(parsed.BaselineReport.Expired) != 0 {
		t.Fatalf("unexpected baseline report: %+v", parsed.BaselineReport)
	}
}

func TestBaselineKeepsSuppressWorking(t *testing.T) {
	input := writeTempYAML(t, "gateways.yaml", brokenGatewaysYaml)
	baselinePath := exportBaselineFor(t, input)

	// Suppressing beta removes it from the diagnostics, so it shows up as
	// disappeared while alpha stays known; the command still succeeds.
	out, err := runAnalyze(t, "--use-kube=false", "--failure-threshold", "ERROR",
		"--baseline", baselinePath, "-S", "IST0106=Gateway default/beta", input)
	if err != nil {
		t.Fatalf("unexpected error: %v\noutput: %s", err, out)
	}
	if !strings.Contains(out, "0 new, 1 known, 1 disappeared, 0 expired") {
		t.Fatalf("expected suppress and baseline to compose, got: %s", out)
	}
}
