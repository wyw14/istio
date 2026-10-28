// Copyright Istio Authors
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

package authz

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"istio.io/istio/istioctl/pkg/cli"
	"istio.io/istio/pilot/pkg/model/authzgraph"
)

func runGraphCmd(t *testing.T, args ...string) string {
	t.Helper()
	cmd := graphCommand(cli.NewFakeContext(nil))
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs(args)
	if err := cmd.Execute(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	return out.String()
}

func graphFiles(t *testing.T) []string {
	t.Helper()
	return []string{
		"testdata/authz-graph/policies.yaml",
		"testdata/authz-graph/resources.yaml",
	}
}

func parseGraph(t *testing.T, out string) *authzgraph.Graph {
	t.Helper()
	g := &authzgraph.Graph{}
	if err := json.Unmarshal([]byte(out), g); err != nil {
		t.Fatalf("output is not valid JSON: %v\n%s", err, out)
	}
	return g
}

func TestGraphCommandOffline(t *testing.T) {
	args := append([]string{"--use-kube=false"}, flattenFiles(graphFiles(t))...)
	g := parseGraph(t, runGraphCmd(t, args...))

	if g.APIVersion != authzgraph.APIVersion || g.Kind != authzgraph.Kind {
		t.Fatalf("unexpected document header: %s %s", g.APIVersion, g.Kind)
	}
	if g.Mesh.RootNamespace != "istio-system" {
		t.Fatalf("root namespace = %q, want istio-system", g.Mesh.RootNamespace)
	}
	if len(g.Policies) != 6 {
		t.Fatalf("expected 6 policy nodes, got %d", len(g.Policies))
	}
	if len(g.Workloads) != 5 {
		t.Fatalf("expected 5 workload nodes, got %d", len(g.Workloads))
	}

	// Root namespace selector policy applies mesh-wide.
	rootPolicy := "policy/istio-system/root-allow"
	httpbinFoo := "workload/foo/httpbin-foo"
	httpbinBar := "workload/bar/httpbin-bar"
	if !edgeExists(g, rootPolicy, httpbinFoo, authzgraph.EdgeAppliesTo) {
		t.Fatalf("root policy must apply to workload in foo")
	}
	if !edgeExists(g, rootPolicy, httpbinBar, authzgraph.EdgeAppliesTo) {
		t.Fatalf("root policy must apply to workload in bar")
	}

	// Namespace policy stays within foo.
	if !edgeExists(g, "policy/foo/ns-deny", httpbinFoo, authzgraph.EdgeAppliesTo) {
		t.Fatalf("namespace deny policy should apply to foo workload")
	}
	if edgeExists(g, "policy/foo/ns-deny", httpbinBar, authzgraph.EdgeAppliesTo) {
		t.Fatalf("namespace deny policy must not cross namespaces")
	}

	// Multi-revision: v2-pinned policy attaches to v2 workload only.
	pinned := "policy/foo/pinned-v2"
	if !edgeExists(g, pinned, "workload/foo/revsvc-v2", authzgraph.EdgeAppliesTo) {
		t.Fatalf("pinned policy should apply to v2 workload")
	}
	if edgeExists(g, pinned, "workload/foo/revsvc-v1", authzgraph.EdgeAppliesTo) {
		t.Fatalf("pinned policy must not apply to v1 workload")
	}

	// Waypoint Service targetRef binds to the waypoint workload.
	wpPolicy := "policy/foo/wp-svc"
	wpWorkload := "workload/foo/wp-pod"
	if !edgeExists(g, wpPolicy, wpWorkload, authzgraph.EdgeAppliesTo) {
		t.Fatalf("Service targetRef policy must apply to the waypoint")
	}
	svcTarget := "target/core/Service/foo/foo-svc"
	if !edgeExists(g, svcTarget, wpWorkload, authzgraph.EdgeBinds) {
		t.Fatalf("Service targetRef should bind to the waypoint")
	}
	var wpNode *authzgraph.WorkloadNode
	for i := range g.Workloads {
		if g.Workloads[i].ID == wpWorkload {
			wpNode = &g.Workloads[i]
		}
	}
	if wpNode == nil || !wpNode.IsWaypoint {
		t.Fatalf("workload not classified as waypoint: %+v", wpNode)
	}

	// Selector-based policies never bind to waypoints.
	if edgeExists(g, "policy/foo/ns-deny", wpWorkload, authzgraph.EdgeAppliesTo) {
		t.Fatalf("namespace-wide selector policy must not apply to a waypoint")
	}

	// Cross-ns and unknown field diagnostics are reported separately.
	codes := map[string]bool{}
	for _, d := range g.Diagnostics {
		codes[d.Code] = true
	}
	if !codes[authzgraph.CodeCrossNamespaceTargetRef] {
		t.Fatalf("missing cross-namespace diagnostic: %+v", codes)
	}
	if !codes[authzgraph.CodeUnknownField] {
		t.Fatalf("missing unknown-field diagnostic: %+v", codes)
	}

	// Override relation between deny and allow on the shared foo workload.
	var foundOverride bool
	for _, e := range g.Edges {
		if e.Type == authzgraph.EdgeOverrides && e.Reason == authzgraph.ReasonDenyPrecedence {
			foundOverride = true
		}
	}
	if !foundOverride {
		t.Fatalf("expected a deny-precedence override edge")
	}
}

func TestGraphCommandStableAndScopedByRevision(t *testing.T) {
	files := graphFiles(t)
	args := append([]string{"--use-kube=false"}, flattenFiles(files)...)
	first := runGraphCmd(t, args...)
	second := runGraphCmd(t, args...)
	if first != second {
		t.Fatalf("graph output must be stable across runs")
	}

	// Revision scoping drops everything but the v2 workload.
	scopedArgs := append([]string{"--use-kube=false", "--revision", "v2"}, flattenFiles(files)...)
	g := parseGraph(t, runGraphCmd(t, scopedArgs...))
	if len(g.Workloads) != 1 || g.Workloads[0].ID != "workload/foo/revsvc-v2" {
		t.Fatalf("revision scope should leave a single workload, got %+v", g.Workloads)
	}
}

func TestGraphCommandRejectsBadOutput(t *testing.T) {
	cmd := graphCommand(cli.NewFakeContext(nil))
	cmd.SetArgs(append([]string{"--use-kube=false", "-o", "yaml"}, flattenFiles(graphFiles(t))...))
	if err := cmd.Execute(); err == nil || !strings.Contains(err.Error(), "unsupported output format") {
		t.Fatalf("expected unsupported format error, got %v", err)
	}
}

func edgeExists(g *authzgraph.Graph, from, to, typ string) bool {
	for _, e := range g.Edges {
		if e.From == from && e.To == to && e.Type == typ {
			return true
		}
	}
	return false
}

func flattenFiles(files []string) []string {
	var out []string
	for _, f := range files {
		out = append(out, "-f", f)
	}
	return out
}
