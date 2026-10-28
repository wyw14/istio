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

package authzgraph

import (
	"encoding/json"
	"strings"
	"testing"

	"istio.io/api/label"
	authpb "istio.io/api/security/v1beta1"
	selectorpb "istio.io/api/type/v1beta1"
	"istio.io/istio/pilot/pkg/model"
	"istio.io/istio/pilot/pkg/serviceregistry/provider"
	"istio.io/istio/pkg/config"
	"istio.io/istio/pkg/config/constants"
	"istio.io/istio/pkg/config/labels"
	"istio.io/istio/pkg/config/schema/gvk"
)

const rootNamespace = "istio-system"

func policyConfig(name, ns string, spec *authpb.AuthorizationPolicy, lbls map[string]string) config.Config {
	return config.Config{
		Meta: config.Meta{
			GroupVersionKind: gvk.AuthorizationPolicy,
			Name:             name,
			Namespace:        ns,
			Labels:           lbls,
			Annotations:      nil,
		},
		Spec: spec,
	}
}

func allowGet(selector map[string]string) *authpb.AuthorizationPolicy {
	p := &authpb.AuthorizationPolicy{
		Action: authpb.AuthorizationPolicy_ALLOW,
		Rules: []*authpb.Rule{{
			To: []*authpb.Rule_To{{Operation: &authpb.Operation{Methods: []string{"GET"}}}},
		}},
	}
	if selector != nil {
		p.Selector = &selectorpb.WorkloadSelector{MatchLabels: selector}
	}
	return p
}

func denyAll() *authpb.AuthorizationPolicy {
	return &authpb.AuthorizationPolicy{Action: authpb.AuthorizationPolicy_DENY, Rules: []*authpb.Rule{{}}}
}

func findEdge(g *Graph, from, to, typ string) *Edge {
	for i := range g.Edges {
		if g.Edges[i].From == from && g.Edges[i].To == to && g.Edges[i].Type == typ {
			return &g.Edges[i]
		}
	}
	return nil
}

func diagnosticCodes(g *Graph) map[string]int {
	out := map[string]int{}
	for _, d := range g.Diagnostics {
		out[d.Code]++
	}
	return out
}

func TestBuildRootNamespacePolicyAppliesMeshWide(t *testing.T) {
	in := &Input{
		RootNamespace: rootNamespace,
		Policies: []PolicyInput{
			{Config: policyConfig("root-policy", rootNamespace, allowGet(map[string]string{"app": "httpbin"}), nil)},
			{Config: policyConfig("ns-deny", "foo", denyAll(), nil)},
		},
		Workloads: []Workload{
			{Name: "w-foo", Namespace: "foo", Labels: labels.Instance{"app": "httpbin"}},
			{Name: "w-bar", Namespace: "bar", Labels: labels.Instance{"app": "httpbin"}},
			{Name: "w-nomatch", Namespace: "baz", Labels: labels.Instance{"app": "other"}},
		},
	}
	g := Build(in)

	pRoot := policyID(ObjectRef{Namespace: rootNamespace, Name: "root-policy"})
	pDeny := policyID(ObjectRef{Namespace: "foo", Name: "ns-deny"})
	wFoo := workloadID(ObjectRef{Namespace: "foo", Name: "w-foo"})
	wBar := workloadID(ObjectRef{Namespace: "bar", Name: "w-bar"})
	wBaz := workloadID(ObjectRef{Namespace: "baz", Name: "w-nomatch"})

	if findEdge(g, pRoot, wFoo, EdgeAppliesTo) == nil {
		t.Fatalf("root namespace policy should apply to workload in foo")
	}
	if findEdge(g, pRoot, wBar, EdgeAppliesTo) == nil {
		t.Fatalf("root namespace policy should apply to workload in bar")
	}
	if findEdge(g, pRoot, wBaz, EdgeAppliesTo) != nil {
		t.Fatalf("selector mismatch: root policy must not apply to w-nomatch")
	}
	if findEdge(g, pDeny, wBar, EdgeAppliesTo) != nil {
		t.Fatalf("namespace policy in foo must not apply to workload in bar")
	}
	if findEdge(g, pDeny, wFoo, EdgeAppliesTo) == nil {
		t.Fatalf("namespace policy should apply to workload in foo")
	}

	// selector -> workload selection edges must exist for the explicit root selector
	selRoot := selectorID(ObjectRef{Namespace: rootNamespace, Name: "root-policy"})
	if findEdge(g, selRoot, wFoo, EdgeSelects) == nil || findEdge(g, selRoot, wBar, EdgeSelects) == nil {
		t.Fatalf("root selector should select workloads in both namespaces")
	}

	var rootNode *PolicyNode
	for i := range g.Policies {
		if g.Policies[i].ID == pRoot {
			rootNode = &g.Policies[i]
		}
	}
	if rootNode == nil || rootNode.Scope != scopeMesh {
		t.Fatalf("root policy scope = %v, want mesh", rootNode)
	}

	// Operation node reflects the GET matcher.
	opID := operationID(ObjectRef{Namespace: rootNamespace, Name: "root-policy"}, 0, 0)
	var op *OperationNode
	for i := range g.Operations {
		if g.Operations[i].ID == opID {
			op = &g.Operations[i]
		}
	}
	if op == nil || len(op.Methods) != 1 || op.Methods[0] != "GET" {
		t.Fatalf("operation node missing GET matcher: %+v", op)
	}
}

func TestBuildWaypointAttachments(t *testing.T) {
	svcTarget := &selectorpb.PolicyTargetReference{Group: gvk.Service.Group, Kind: gvk.Service.Kind, Name: "foo-svc"}
	seTarget := &selectorpb.PolicyTargetReference{Group: gvk.ServiceEntry.Group, Kind: gvk.ServiceEntry.Kind, Name: "ext-svc"}
	classTarget := &selectorpb.PolicyTargetReference{Group: gvk.GatewayClass.Group, Kind: gvk.GatewayClass.Kind, Name: constants.WaypointGatewayClassName}

	svcPolicy := allowGet(nil)
	svcPolicy.TargetRef = svcTarget
	sePolicy := allowGet(nil)
	sePolicy.TargetRef = seTarget
	classPolicy := allowGet(nil)
	classPolicy.TargetRef = classTarget
	selectorPolicy := allowGet(map[string]string{"app": "foo"})

	in := &Input{
		RootNamespace: rootNamespace,
		Policies: []PolicyInput{
			{Config: policyConfig("wp-svc", "foo", svcPolicy, nil)},
			{Config: policyConfig("wp-se", "foo", sePolicy, nil)},
			{Config: policyConfig("wp-class", rootNamespace, classPolicy, nil)},
			{Config: policyConfig("wp-selector", "foo", selectorPolicy, nil)},
		},
		Workloads: []Workload{{
			Name:       "wp-1",
			Namespace:  "foo",
			IsWaypoint: true,
			Labels:     labels.Instance{label.IoK8sNetworkingGatewayGatewayName.Name: "wp"},
			Services: []model.ServiceInfoForPolicyMatcher{
				{Name: "foo-svc", Namespace: "foo", Registry: provider.Kubernetes},
				{Name: "ext-svc", Namespace: "foo", Registry: provider.External},
			},
		}},
		Services: []Service{
			{Name: "foo-svc", Namespace: "foo", Registry: provider.Kubernetes},
			{Name: "ext-svc", Namespace: "foo", Registry: provider.External},
		},
		GatewayClasses: []string{constants.WaypointGatewayClassName},
	}
	g := Build(in)

	wl := workloadID(ObjectRef{Namespace: "foo", Name: "wp-1"})
	pSvc := policyID(ObjectRef{Namespace: "foo", Name: "wp-svc"})
	pSE := policyID(ObjectRef{Namespace: "foo", Name: "wp-se"})
	pClass := policyID(ObjectRef{Namespace: rootNamespace, Name: "wp-class"})
	pSelector := policyID(ObjectRef{Namespace: "foo", Name: "wp-selector"})

	if findEdge(g, pSvc, wl, EdgeAppliesTo) == nil {
		t.Fatalf("Service targetRef policy must apply to waypoint")
	}
	if findEdge(g, pSE, wl, EdgeAppliesTo) == nil {
		t.Fatalf("ServiceEntry targetRef policy must apply to waypoint")
	}
	if findEdge(g, pClass, wl, EdgeAppliesTo) == nil {
		t.Fatalf("root GatewayClass targetRef policy must apply to every waypoint")
	}
	if findEdge(g, pSelector, wl, EdgeAppliesTo) != nil {
		t.Fatalf("selector-based policies must never apply to waypoints")
	}

	svcNode := targetID(config.CanonicalGroup(gvk.Service.Group), gvk.Service.Kind, "foo", "foo-svc")
	if findEdge(g, svcNode, wl, EdgeBinds) == nil {
		t.Fatalf("Service target should bind to waypoint workload")
	}
	classNode := targetID(config.CanonicalGroup(gvk.GatewayClass.Group), gvk.GatewayClass.Kind, rootNamespace, constants.WaypointGatewayClassName)
	if findEdge(g, classNode, wl, EdgeBinds) == nil {
		t.Fatalf("GatewayClass target should bind the waypoint")
	}

	// No diagnostics expected: all references resolve and bind.
	if codes := diagnosticCodes(g); len(codes) != 0 {
		t.Fatalf("unexpected diagnostics: %+v", codes)
	}
}

func TestBuildMultiRevision(t *testing.T) {
	gwTarget := &selectorpb.PolicyTargetReference{
		Group: gvk.KubernetesGateway.Group, Kind: gvk.KubernetesGateway.Kind, Name: "gw",
	}
	gwPolicy := allowGet(nil)
	gwPolicy.TargetRef = gwTarget

	in := &Input{
		RootNamespace: rootNamespace,
		Policies: []PolicyInput{
			// Unpinned namespace-wide policy: visible to every revision.
			{Config: policyConfig("global", "foo", denyAll(), nil)},
			// Pinned policy: visible only to v2 proxies.
			{Config: policyConfig("pinned-v2", "foo", denyAll(), map[string]string{label.IoIstioRev.Name: "v2"})},
			// Unpinned targetRef policy in a multi-revision mesh: pinning hint.
			{Config: policyConfig("gw-policy", "foo", gwPolicy, nil)},
		},
		Workloads: []Workload{
			{Name: "w-v1", Namespace: "foo", Revision: "v1",
				Labels: labels.Instance{}},
			{Name: "w-v2", Namespace: "foo", Revision: "v2",
				Labels: labels.Instance{}},
		},
		Gateways: []Gateway{{Name: "gw", Namespace: "foo", GatewayClassName: constants.WaypointGatewayClassName}},
	}
	g := Build(in)

	wV1 := workloadID(ObjectRef{Namespace: "foo", Name: "w-v1"})
	wV2 := workloadID(ObjectRef{Namespace: "foo", Name: "w-v2"})
	pGlobal := policyID(ObjectRef{Namespace: "foo", Name: "global"})
	pPinned := policyID(ObjectRef{Namespace: "foo", Name: "pinned-v2"})

	if findEdge(g, pGlobal, wV1, EdgeAppliesTo) == nil || findEdge(g, pGlobal, wV2, EdgeAppliesTo) == nil {
		t.Fatalf("unpinned policy must apply to both revisions")
	}
	if findEdge(g, pPinned, wV1, EdgeAppliesTo) != nil {
		t.Fatalf("v2-pinned policy must not apply to v1 workload")
	}
	if findEdge(g, pPinned, wV2, EdgeAppliesTo) == nil {
		t.Fatalf("v2-pinned policy must apply to v2 workload")
	}
	if len(g.Mesh.Revisions) != 2 || g.Mesh.Revisions[0] != "v1" || g.Mesh.Revisions[1] != "v2" {
		t.Fatalf("mesh revisions = %v, want [v1 v2]", g.Mesh.Revisions)
	}
	codes := diagnosticCodes(g)
	if codes[CodePinTargetRefRevision] == 0 {
		t.Fatalf("expected revision pinning hint for unpinned targetRef policy, got %+v", codes)
	}
}

func TestBuildOverrideRelations(t *testing.T) {
	allow1 := policyConfig("allow-1", "foo", denyAll(), nil)
	allow1.Spec.(*authpb.AuthorizationPolicy).Action = authpb.AuthorizationPolicy_ALLOW
	allow2 := policyConfig("allow-2", "foo", denyAll(), nil)
	allow2.Spec.(*authpb.AuthorizationPolicy).Action = authpb.AuthorizationPolicy_ALLOW
	deny := policyConfig("deny-1", "foo", denyAll(), nil) // DENY

	in := &Input{
		RootNamespace: rootNamespace,
		Policies:      []PolicyInput{{Config: allow1}, {Config: allow2}, {Config: deny}},
		Workloads:     []Workload{{Name: "w", Namespace: "foo", Labels: labels.Instance{}}},
	}
	g := Build(in)

	wl := workloadID(ObjectRef{Namespace: "foo", Name: "w"})
	denyID := policyID(ObjectRef{Namespace: "foo", Name: "deny-1"})
	a1 := policyID(ObjectRef{Namespace: "foo", Name: "allow-1"})
	a2 := policyID(ObjectRef{Namespace: "foo", Name: "allow-2"})

	over := findEdge(g, denyID, a1, EdgeOverrides)
	if over == nil || over.Reason != ReasonDenyPrecedence {
		t.Fatalf("expected deny-overrides-allow edge, got %+v", over)
	}
	if len(over.Workloads) != 1 || over.Workloads[0] != wl {
		t.Fatalf("override edge should list the shared workload, got %+v", over.Workloads)
	}
	comb := findEdge(g, a1, a2, EdgeCombines)
	if comb == nil || comb.Reason != ReasonSameActionOR {
		t.Fatalf("expected same-action combines edge, got %+v", comb)
	}
}

func TestDiagnoseCrossNamespaceTargetRef(t *testing.T) {
	ref := &selectorpb.PolicyTargetReference{
		Group:     gvk.KubernetesGateway.Group,
		Kind:      gvk.KubernetesGateway.Kind,
		Name:      "gw",
		Namespace: "bar",
	}
	p := allowGet(nil)
	p.TargetRef = ref
	in := &Input{
		RootNamespace: rootNamespace,
		Policies:      []PolicyInput{{Config: policyConfig("xns", "foo", p, nil)}},
		Workloads: []Workload{{
			Name: "gw-pod", Namespace: "foo",
			Labels: labels.Instance{label.IoK8sNetworkingGatewayGatewayName.Name: "gw"},
		}},
	}
	g := Build(in)
	codes := diagnosticCodes(g)
	if codes[CodeCrossNamespaceTargetRef] == 0 {
		t.Fatalf("expected cross-namespace diagnostic, got %+v", codes)
	}
	pID := policyID(ObjectRef{Namespace: "foo", Name: "xns"})
	wl := workloadID(ObjectRef{Namespace: "foo", Name: "gw-pod"})
	if findEdge(g, pID, wl, EdgeAppliesTo) != nil {
		t.Fatalf("cross-namespace targetRef policy must never bind")
	}
}

func TestDiagnoseUnsupportedKindAndUnresolved(t *testing.T) {
	ref := &selectorpb.PolicyTargetReference{Group: "apps", Kind: "Deployment", Name: "dep"}
	p := allowGet(nil)
	p.TargetRef = ref
	g := Build(&Input{
		RootNamespace: rootNamespace,
		Policies:      []PolicyInput{{Config: policyConfig("bad", "foo", p, nil)}},
	})
	codes := diagnosticCodes(g)
	if codes[CodeUnsupportedTargetKind] == 0 {
		t.Fatalf("expected unsupported target kind diagnostic, got %+v", codes)
	}

	// Known kind but object missing -> unresolved, and no binds.
	svc := allowGet(nil)
	svc.TargetRef = &selectorpb.PolicyTargetReference{Group: gvk.Service.Group, Kind: gvk.Service.Kind, Name: "missing"}
	g2 := Build(&Input{
		RootNamespace: rootNamespace,
		Policies:      []PolicyInput{{Config: policyConfig("missing-svc", "foo", svc, nil)}},
		Workloads:     []Workload{{Name: "wp", Namespace: "foo", IsWaypoint: true, Labels: labels.Instance{}}},
	})
	c2 := diagnosticCodes(g2)
	if c2[CodeUnresolvedTargetRef] == 0 {
		t.Fatalf("expected unresolved targetRef diagnostic, got %+v", c2)
	}
}

func TestDiagnoseUnknownFields(t *testing.T) {
	spec := allowGet(map[string]string{"app": "httpbin"})
	raw := map[string]any{
		"apiVersion": "security.istio.io/v1beta1",
		"kind":       "AuthorizationPolicy",
		"metadata":   map[string]any{"name": "typo", "namespace": "foo"},
		"spec": map[string]any{
			"acshion": "ALLOW",
			"rules": []any{
				map[string]any{
					"to": []any{
						map[string]any{"operation": map[string]any{"mothods": []any{"GET"}, "methods": []any{"GET"}}},
					},
				},
			},
		},
	}
	g := Build(&Input{
		RootNamespace: rootNamespace,
		Policies:      []PolicyInput{{Config: policyConfig("typo", "foo", spec, nil), Raw: raw}},
	})
	var paths []string
	for _, d := range g.Diagnostics {
		if d.Code == CodeUnknownField {
			paths = append(paths, d.FieldPath)
			// Map fields such as selector.matchLabels have arbitrary keys.
			if strings.Contains(d.FieldPath, "matchLabels") {
				t.Fatalf("matchLabels keys must never be reported as unknown fields: %s", d.FieldPath)
			}
		}
	}
	want := map[string]bool{
		"spec.acshion":                          false,
		"spec.rules[0].to[0].operation.mothods": false,
	}
	for _, p := range paths {
		if _, ok := want[p]; ok {
			want[p] = true
		}
	}
	for k, found := range want {
		if !found {
			t.Fatalf("missing unknown-field diagnostic for %s; got %v", k, paths)
		}
	}
}

func TestDiagnoseUnsupportedCondition(t *testing.T) {
	p := &authpb.AuthorizationPolicy{
		Action: authpb.AuthorizationPolicy_DENY,
		Rules: []*authpb.Rule{{
			When: []*authpb.Condition{{Key: "request.bogus", Values: []string{"x"}}},
		}},
	}
	g := Build(&Input{
		RootNamespace: rootNamespace,
		Policies:      []PolicyInput{{Config: policyConfig("bad-when", "foo", p, nil)}},
	})
	if codes := diagnosticCodes(g); codes[CodeUnsupportedConditionAttribute] == 0 {
		t.Fatalf("expected unsupported condition diagnostic, got %+v", codes)
	}
}

func TestAllowNothingPolicyAndImplicitOperation(t *testing.T) {
	// ALLOW policy with zero rules: matches nothing (allow-nothing), no operation nodes.
	empty := &authpb.AuthorizationPolicy{Action: authpb.AuthorizationPolicy_ALLOW}
	g := Build(&Input{
		RootNamespace: rootNamespace,
		Policies:      []PolicyInput{{Config: policyConfig("allow-nothing", "foo", empty, nil)}},
		Workloads:     []Workload{{Name: "w", Namespace: "foo", Labels: labels.Instance{}}},
	})
	var node *PolicyNode
	for i := range g.Policies {
		if g.Policies[i].ID == policyID(ObjectRef{Namespace: "foo", Name: "allow-nothing"}) {
			node = &g.Policies[i]
		}
	}
	if node == nil || node.RuleCount != 0 {
		t.Fatalf("expected 0 rules, got %+v", node)
	}
	for _, op := range g.Operations {
		if op.Policy.Name == "allow-nothing" {
			t.Fatalf("expected no operation nodes for rule-less policy, got %+v", op)
		}
	}

	// A rule without a "to" clause yields one implicit any-operation node.
	implicit := policyConfig("any-op", "foo", denyAll(), nil)
	g2 := Build(&Input{
		RootNamespace: rootNamespace,
		Policies:      []PolicyInput{{Config: implicit}},
	})
	opID := operationID(ObjectRef{Namespace: "foo", Name: "any-op"}, 0, -1)
	found := false
	for _, op := range g2.Operations {
		if op.ID == opID {
			found = op.Implicit
		}
	}
	if !found {
		t.Fatalf("expected implicit operation node %s", opID)
	}
}

func TestStableJSON(t *testing.T) {
	mk := func() *Input {
		return &Input{
			RootNamespace: rootNamespace,
			// Deliberately shuffled declaration order.
			Policies: []PolicyInput{
				{Config: policyConfig("z-policy", "foo", denyAll(), nil)},
				{Config: policyConfig("a-policy", "foo", allowGet(nil), nil)},
			},
			Workloads: []Workload{
				{Name: "w2", Namespace: "foo", Labels: labels.Instance{"z": "z", "a": "a"}},
				{Name: "w1", Namespace: "foo", Labels: labels.Instance{"a": "a"}},
			},
		}
	}
	first, err := json.Marshal(Build(mk()))
	if err != nil {
		t.Fatal(err)
	}
	second, err := json.Marshal(Build(mk()))
	if err != nil {
		t.Fatal(err)
	}
	if string(first) != string(second) {
		t.Fatalf("graph JSON is not stable across builds\n%s\nvs\n%s", first, second)
	}
	var generic map[string]any
	if err := json.Unmarshal(first, &generic); err != nil {
		t.Fatalf("output must be valid JSON: %v", err)
	}
	if generic["apiVersion"] != APIVersion || generic["kind"] != Kind {
		t.Fatalf("unexpected document header: %v %v", generic["apiVersion"], generic["kind"])
	}
}
