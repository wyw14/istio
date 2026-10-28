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

// Package authzgraph builds a read-only dependency graph of AuthorizationPolicy
// resources. The graph connects policies to the workloads they select (reusing the
// exact attachment logic of pilot/pkg/model), the operations and sources declared in
// their rules (validated through pilot/pkg/security/authz/model), and their targetRef
// bindings. It also reports diagnostics for cross-namespace target references and for
// fields unknown to the AuthorizationPolicy schema.
//
// The package never performs or mutates authorization computation: it only calls the
// same selection helpers that are used when generating Envoy configuration.
package authzgraph

import (
	"sort"
	"strings"

	"k8s.io/apimachinery/pkg/types"

	"istio.io/api/label"
	"istio.io/api/security/v1beta1"
	selectorpb "istio.io/api/type/v1beta1"
	"istio.io/istio/pilot/pkg/features"
	"istio.io/istio/pilot/pkg/model"
	"istio.io/istio/pilot/pkg/serviceregistry/provider"
	"istio.io/istio/pkg/config"
	"istio.io/istio/pkg/config/constants"
	"istio.io/istio/pkg/config/labels"
	"istio.io/istio/pkg/config/schema/gvk"
)

const (
	// APIVersion is the version of the stable JSON graph format.
	APIVersion = "authz.istio.io/v1alpha1"
	// Kind is the Kubernetes-style kind of the graph document.
	Kind = "AuthorizationPolicyDependencyGraph"

	// Node ID prefixes.
	policyPrefix    = "policy/"
	workloadPrefix  = "workload/"
	selectorPrefix  = "selector/"
	operationPrefix = "operation/"
	targetPrefix    = "target"

	// Scopes.
	scopeMesh      = "mesh"
	scopeNamespace = "namespace"
	scopeTargetRef = "target-ref"

	// Edge types.
	EdgeHasSelector = "has-selector"
	EdgeSelects     = "selects"
	EdgeTargets     = "targets"
	EdgeBinds       = "binds"
	EdgeAppliesTo   = "applies-to"
	EdgeMatchesOp   = "matches-operation"
	EdgeOverrides   = "overrides"
	EdgeCombines    = "combines"
	EdgeRelates     = "relates"

	// Override/relation reasons.
	ReasonCustomFirst    = "custom-evaluated-first"
	ReasonDenyPrecedence = "deny-precedence"
	ReasonSameActionOR   = "same-action-or-semantics"
	ReasonDenyAndAudit   = "deny-and-audit"
	ReasonAllowAndAudit  = "allow-and-audit"

	// Target ref resolution kinds.
	ResolutionService      = "service"
	ResolutionServiceEntry = "service-entry"
	ResolutionGateway      = "gateway"
	ResolutionGatewayClass = "gateway-class"
	ResolutionHTTPRoute    = "http-route"
	ResolutionUnsupported  = "unsupported"

	dryRunAnnotation = "istio.io/dry-run"
)

// ObjectRef references a namespace-scoped object.
type ObjectRef struct {
	Namespace string `json:"namespace"`
	Name      string `json:"name"`
}

// Mesh describes mesh-wide context used while building the graph.
type Mesh struct {
	// RootNamespace is the configured mesh root namespace; policies in it apply to
	// workloads in every namespace.
	RootNamespace string `json:"rootNamespace"`
	// Revisions observed on the workloads in the graph, sorted and deduplicated.
	Revisions []string `json:"revisions,omitempty"`
}

// PolicyNode describes a single AuthorizationPolicy.
type PolicyNode struct {
	ID     string    `json:"id"`
	Ref    ObjectRef `json:"ref"`
	Action string    `json:"action"`
	// Scope is "mesh" (policy in the root namespace, selector based), "namespace"
	// (selector based in a regular namespace) or "target-ref" (attached via targetRef(s)).
	Scope string `json:"scope"`
	// Revision pins the policy to proxies of one control-plane revision
	// (the istio.io/rev label). Empty means visible to every revision.
	Revision string `json:"revision,omitempty"`
	// RuleCount is the number of rules declared by the policy. An ALLOW policy with
	// zero rules matches nothing ("allow-nothing").
	RuleCount int `json:"ruleCount"`
	// DryRun is set when the policy carries the istio.io/dry-run annotation.
	DryRun bool `json:"dryRun,omitempty"`
}

// WorkloadNode describes a workload (typically a pod) that policies may select.
type WorkloadNode struct {
	ID         string            `json:"id"`
	Ref        ObjectRef         `json:"ref"`
	Labels     map[string]string `json:"labels,omitempty"`
	Revision   string            `json:"revision,omitempty"`
	IsWaypoint bool              `json:"isWaypoint,omitempty"`
	// GatewayName is the gateway.networking.k8s.io/gateway-name label, when present.
	GatewayName string `json:"gatewayName,omitempty"`
	// Services backing the workload, used by waypoint targetRef attachment.
	Services []model.ServiceInfoForPolicyMatcher `json:"services,omitempty"`
}

// SelectorNode represents the selector (explicit or implicit) of a selector-based policy.
type SelectorNode struct {
	ID     string    `json:"id"`
	Policy ObjectRef `json:"policy"`
	// MatchLabels are the selector match labels. Empty for an implicit selector.
	MatchLabels map[string]string `json:"matchLabels,omitempty"`
	// Scope is "mesh" for a policy in the root namespace (applies to every namespace)
	// and "namespace" otherwise.
	Scope string `json:"scope"`
	// Implicit is true when the policy declares no selector and therefore matches
	// every workload in its scope.
	Implicit bool `json:"implicit,omitempty"`
}

// SourceMatch describes the source part of a rule (the "from" clause).
type SourceMatch struct {
	Principals           []string `json:"principals,omitempty"`
	NotPrincipals        []string `json:"notPrincipals,omitempty"`
	RequestPrincipals    []string `json:"requestPrincipals,omitempty"`
	NotRequestPrincipals []string `json:"notRequestPrincipals,omitempty"`
	Namespaces           []string `json:"namespaces,omitempty"`
	NotNamespaces        []string `json:"notNamespaces,omitempty"`
	ServiceAccounts      []string `json:"serviceAccounts,omitempty"`
	NotServiceAccounts   []string `json:"notServiceAccounts,omitempty"`
	IpBlocks             []string `json:"ipBlocks,omitempty"`
	NotIpBlocks          []string `json:"notIpBlocks,omitempty"`
	RemoteIpBlocks       []string `json:"remoteIpBlocks,omitempty"`
	NotRemoteIpBlocks    []string `json:"notRemoteIpBlocks,omitempty"`
	TrustDomains         []string `json:"trustDomains,omitempty"`
	NotTrustDomains      []string `json:"notTrustDomains,omitempty"`
}

// ConditionMatch describes one "when" condition of a rule.
type ConditionMatch struct {
	Key       string   `json:"key"`
	Values    []string `json:"values,omitempty"`
	NotValues []string `json:"notValues,omitempty"`
}

// OperationNode describes one "to.operation" entry of a rule. When the rule declares no
// "to" entry a single node matching any operation is emitted with Implicit set.
type OperationNode struct {
	ID     string    `json:"id"`
	Policy ObjectRef `json:"policy"`
	// Rule is the zero-based index of the rule within the policy.
	Rule int `json:"rule"`
	// To is the zero-based index of the "to" entry, or -1 for an implicit any-operation.
	To int `json:"to"`
	// Implicit is true when the rule has no "to" clause (any operation matches).
	Implicit bool `json:"implicit,omitempty"`

	Hosts      []string `json:"hosts,omitempty"`
	NotHosts   []string `json:"notHosts,omitempty"`
	Ports      []string `json:"ports,omitempty"`
	NotPorts   []string `json:"notPorts,omitempty"`
	Methods    []string `json:"methods,omitempty"`
	NotMethods []string `json:"notMethods,omitempty"`
	Paths      []string `json:"paths,omitempty"`
	NotPaths   []string `json:"notPaths,omitempty"`

	// Sources holds the rule-level "from" clauses shared with this operation.
	Sources []SourceMatch `json:"sources,omitempty"`
	// Conditions holds the rule-level "when" conditions shared with this operation.
	Conditions []ConditionMatch `json:"conditions,omitempty"`
}

// TargetRefNode describes a resource referenced through targetRef/targetRefs.
type TargetRefNode struct {
	ID string `json:"id"`
	// Policy that references the target.
	Policy ObjectRef `json:"policy"`
	// RefIndex is the index in targetRefs (0 for the legacy targetRef field).
	RefIndex int `json:"refIndex"`
	// Group is the canonical (empty group normalized to "core") API group.
	Group string `json:"group"`
	Kind  string `json:"kind"`
	Name  string `json:"name"`
	// Namespace is the effective namespace: the explicit reference namespace when
	// set, otherwise the policy namespace.
	Namespace string `json:"namespace"`
	// Resolution classifies the referenced kind ("service", "gateway", ...).
	Resolution string `json:"resolution"`
	// Resolved reports whether the referenced object exists in the graph inputs.
	Resolved bool `json:"resolved"`
}

// Edge is a directed relation in the dependency graph.
type Edge struct {
	From   string `json:"from"`
	To     string `json:"to"`
	Type   string `json:"type"`
	Reason string `json:"reason,omitempty"`
	// Action is set on "applies-to" edges.
	Action string `json:"action,omitempty"`
	// Workloads lists workload IDs for which a policy-policy relation holds,
	// sorted and deduplicated.
	Workloads []string `json:"workloads,omitempty"`
}

// Graph is the stable JSON document.
type Graph struct {
	APIVersion  string          `json:"apiVersion"`
	Kind        string          `json:"kind"`
	Mesh        Mesh            `json:"mesh"`
	Policies    []PolicyNode    `json:"policies"`
	Workloads   []WorkloadNode  `json:"workloads"`
	Selectors   []SelectorNode  `json:"selectors"`
	Operations  []OperationNode `json:"operations"`
	TargetRefs  []TargetRefNode `json:"targetRefs"`
	Edges       []Edge          `json:"edges"`
	Diagnostics []Diagnostic    `json:"diagnostics"`
}

// Workload is a graph input describing one workload.
type Workload struct {
	Name       string
	Namespace  string
	Labels     labels.Instance
	Revision   string
	IsWaypoint bool
	// Services the workload backs; required for waypoint targetRef(Service/ServiceEntry)
	// attachment, mirroring model.WorkloadPolicyMatcher.Services.
	Services []model.ServiceInfoForPolicyMatcher
}

// Service describes a Service or ServiceEntry that may be referenced through targetRef.
type Service struct {
	Name      string
	Namespace string
	// Registry is provider.Kubernetes for a core Service and provider.External for a
	// ServiceEntry.
	Registry provider.ID
}

// Gateway describes a Kubernetes Gateway that may be referenced through targetRef.
type Gateway struct {
	Name             string
	Namespace        string
	GatewayClassName string
	Revision         string
}

// PolicyInput is an AuthorizationPolicy config optionally accompanied by its raw decoded
// object (as produced from YAML/JSON). The raw object is only used to detect unknown
// fields and must be nil when the raw representation is not available.
type PolicyInput struct {
	Config config.Config
	// Raw is the whole decoded object, including its "spec" subtree.
	Raw map[string]any
}

// Input holds everything required to build the dependency graph.
type Input struct {
	// RootNamespace is the mesh root namespace.
	RootNamespace string
	// Policies are the AuthorizationPolicy resources to include.
	Policies []PolicyInput
	// Workloads are the workloads against which policy selection is evaluated.
	Workloads []Workload
	// Services lists existing Services/ServiceEntries for targetRef resolution.
	Services []Service
	// Gateways lists existing Kubernetes Gateways for targetRef resolution.
	Gateways []Gateway
	// GatewayClasses lists existing GatewayClass names.
	GatewayClasses []string
	// HTTPRoutes lists existing HTTPRoutes referenced through targetRef.
	HTTPRoutes []types.NamespacedName
}

type policyEntry struct {
	cfg  config.Config
	spec *v1beta1.AuthorizationPolicy
	raw  map[string]any
	ref  ObjectRef
}

type builder struct {
	in *Input

	policies []*policyEntry
	byKey    map[types.NamespacedName]*policyEntry

	g Graph

	// target nodes keyed by their canonical ID, preserving insertion order per policy.
	targets map[string]*TargetRefNode
	// refIndex records every targetRef of a policy, in declaration order.
	refIndex map[ObjectRef][]refIndexEntry
	// relation pair key -> relation accumulator.
	relations map[string]*relation
}

type refIndexEntry struct {
	index      int
	nodeID     string
	ref        *selectorpb.PolicyTargetReference
	namespace  string
	resolution string
}

type relation struct {
	from, to      string
	typ, reason   string
	workloads     []string
	seenWorkloads map[string]bool
}

// Build constructs the dependency graph. It is deterministic and side-effect free.
func Build(in *Input) *Graph {
	b := &builder{
		in:        in,
		byKey:     map[types.NamespacedName]*policyEntry{},
		targets:   map[string]*TargetRefNode{},
		refIndex:  map[ObjectRef][]refIndexEntry{},
		relations: map[string]*relation{},
	}
	b.g = Graph{
		APIVersion: APIVersion,
		Kind:       Kind,
		Mesh: Mesh{
			RootNamespace: in.RootNamespace,
		},
		Policies:    []PolicyNode{},
		Workloads:   []WorkloadNode{},
		Selectors:   []SelectorNode{},
		Operations:  []OperationNode{},
		TargetRefs:  []TargetRefNode{},
		Edges:       []Edge{},
		Diagnostics: []Diagnostic{},
	}

	b.collectPolicies()
	b.collectWorkloads()
	b.buildStaticNodes()
	b.evaluateAttachments()
	b.emitRelations()
	b.diagnose()
	b.sort()
	return &b.g
}

func policyID(ref ObjectRef) string { return policyPrefix + ref.Namespace + "/" + ref.Name }

func workloadID(ref ObjectRef) string { return workloadPrefix + ref.Namespace + "/" + ref.Name }

func selectorID(ref ObjectRef) string { return selectorPrefix + ref.Namespace + "/" + ref.Name }

func operationID(ref ObjectRef, rule, to int) string {
	return operationPrefix + ref.Namespace + "/" + ref.Name + "/r" + itoa(rule) + "/t" + itoa(to)
}

func targetID(group, kind, namespace, name string) string {
	return strings.Join([]string{targetPrefix, group, kind, namespace, name}, "/")
}

func (b *builder) collectPolicies() {
	for _, p := range b.in.Policies {
		spec, ok := p.Config.Spec.(*v1beta1.AuthorizationPolicy)
		if !ok {
			b.g.Diagnostics = append(b.g.Diagnostics, Diagnostic{
				Code:      CodeInternalTypeError,
				Severity:  SeverityError,
				Resource:  &ObjectRef{Namespace: p.Config.Namespace, Name: p.Config.Name},
				FieldPath: "",
				Message:   "config is not an AuthorizationPolicy",
			})
			continue
		}
		ref := ObjectRef{Namespace: p.Config.Namespace, Name: p.Config.Name}
		entry := &policyEntry{
			cfg:  p.Config,
			spec: spec,
			raw:  p.Raw,
			ref:  ref,
		}
		b.policies = append(b.policies, entry)
		b.byKey[types.NamespacedName{Namespace: ref.Namespace, Name: ref.Name}] = entry
	}
}

func (b *builder) collectWorkloads() {
	revisions := map[string]bool{}
	for _, w := range b.in.Workloads {
		if w.Revision != "" {
			revisions[w.Revision] = true
		}
	}
	for rev := range revisions {
		b.g.Mesh.Revisions = append(b.g.Mesh.Revisions, rev)
	}
	sort.Strings(b.g.Mesh.Revisions)
}

func actionName(a v1beta1.AuthorizationPolicy_Action) string {
	switch a {
	case v1beta1.AuthorizationPolicy_ALLOW:
		return "ALLOW"
	case v1beta1.AuthorizationPolicy_DENY:
		return "DENY"
	case v1beta1.AuthorizationPolicy_AUDIT:
		return "AUDIT"
	case v1beta1.AuthorizationPolicy_CUSTOM:
		return "CUSTOM"
	default:
		return "UNKNOWN"
	}
}

func (b *builder) policyScope(e *policyEntry) string {
	if len(model.GetTargetRefs(e.spec)) > 0 {
		return scopeTargetRef
	}
	if e.ref.Namespace == b.in.RootNamespace {
		return scopeMesh
	}
	return scopeNamespace
}

// buildStaticNodes emits policy, selector, operation and targetRef nodes plus the
// edges that are independent of observed workloads.
func (b *builder) buildStaticNodes() {
	for _, e := range b.policies {
		b.g.Policies = append(b.g.Policies, PolicyNode{
			ID:        policyID(e.ref),
			Ref:       e.ref,
			Action:    actionName(e.spec.GetAction()),
			Scope:     b.policyScope(e),
			Revision:  e.cfg.Labels[label.IoIstioRev.Name],
			RuleCount: len(e.spec.GetRules()),
			DryRun:    e.cfg.Annotations[dryRunAnnotation] == "true",
		})

		// Selector node (explicit or implicit) for selector-based policies.
		if len(model.GetTargetRefs(e.spec)) == 0 {
			sel := e.spec.GetSelector()
			node := SelectorNode{
				ID:          selectorID(e.ref),
				Policy:      e.ref,
				MatchLabels: cloneSortedLabels(sel.GetMatchLabels()),
				Scope:       b.policyScope(e),
				Implicit:    sel == nil,
			}
			b.g.Selectors = append(b.g.Selectors, node)
			b.g.Edges = append(b.g.Edges, Edge{
				From: policyID(e.ref),
				To:   node.ID,
				Type: EdgeHasSelector,
			})
		}

		b.buildOperationNodes(e)
		b.buildTargetNodes(e)
	}
}

func cloneSortedLabels(in map[string]string) map[string]string {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func sortedCopy(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	out := append([]string{}, in...)
	sort.Strings(out)
	return out
}

func (b *builder) buildOperationNodes(e *policyEntry) {
	sources := func(rule *v1beta1.Rule) []SourceMatch {
		if len(rule.GetFrom()) == 0 {
			return nil
		}
		out := make([]SourceMatch, 0, len(rule.GetFrom()))
		for _, from := range rule.GetFrom() {
			s := from.GetSource()
			if s == nil {
				continue
			}
			out = append(out, SourceMatch{
				Principals:           sortedCopy(s.GetPrincipals()),
				NotPrincipals:        sortedCopy(s.GetNotPrincipals()),
				RequestPrincipals:    sortedCopy(s.GetRequestPrincipals()),
				NotRequestPrincipals: sortedCopy(s.GetNotRequestPrincipals()),
				Namespaces:           sortedCopy(s.GetNamespaces()),
				NotNamespaces:        sortedCopy(s.GetNotNamespaces()),
				ServiceAccounts:      sortedCopy(s.GetServiceAccounts()),
				NotServiceAccounts:   sortedCopy(s.GetNotServiceAccounts()),
				IpBlocks:             sortedCopy(s.GetIpBlocks()),
				NotIpBlocks:          sortedCopy(s.GetNotIpBlocks()),
				RemoteIpBlocks:       sortedCopy(s.GetRemoteIpBlocks()),
				NotRemoteIpBlocks:    sortedCopy(s.GetNotRemoteIpBlocks()),
				TrustDomains:         sortedCopy(s.GetTrustDomains()),
				NotTrustDomains:      sortedCopy(s.GetNotTrustDomains()),
			})
		}
		return out
	}
	conditions := func(rule *v1beta1.Rule) []ConditionMatch {
		if len(rule.GetWhen()) == 0 {
			return nil
		}
		out := make([]ConditionMatch, 0, len(rule.GetWhen()))
		for _, when := range rule.GetWhen() {
			out = append(out, ConditionMatch{
				Key:       when.GetKey(),
				Values:    sortedCopy(when.GetValues()),
				NotValues: sortedCopy(when.GetNotValues()),
			})
		}
		return out
	}

	addNode := func(node OperationNode) {
		b.g.Operations = append(b.g.Operations, node)
		b.g.Edges = append(b.g.Edges, Edge{
			From: policyID(e.ref),
			To:   node.ID,
			Type: EdgeMatchesOp,
		})
	}
	for ri, rule := range e.spec.GetRules() {
		tos := rule.GetTo()
		if len(tos) == 0 {
			addNode(OperationNode{
				ID:         operationID(e.ref, ri, -1),
				Policy:     e.ref,
				Rule:       ri,
				To:         -1,
				Implicit:   true,
				Sources:    sources(rule),
				Conditions: conditions(rule),
			})
			continue
		}
		for ti, to := range tos {
			op := to.GetOperation()
			node := OperationNode{
				ID:         operationID(e.ref, ri, ti),
				Policy:     e.ref,
				Rule:       ri,
				To:         ti,
				Sources:    sources(rule),
				Conditions: conditions(rule),
			}
			if op != nil {
				node.Hosts = sortedCopy(op.GetHosts())
				node.NotHosts = sortedCopy(op.GetNotHosts())
				node.Ports = sortedCopy(op.GetPorts())
				node.NotPorts = sortedCopy(op.GetNotPorts())
				node.Methods = sortedCopy(op.GetMethods())
				node.NotMethods = sortedCopy(op.GetNotMethods())
				node.Paths = sortedCopy(op.GetPaths())
				node.NotPaths = sortedCopy(op.GetNotPaths())
			}
			addNode(node)
		}
	}
}

func (b *builder) buildTargetNodes(e *policyEntry) {
	for i, ref := range model.GetTargetRefs(e.spec) {
		group, kind, res := classifyTargetRef(ref)
		ns := ref.GetNamespace()
		if ns == "" {
			ns = e.ref.Namespace
		}
		id := targetID(group, kind, ns, ref.GetName())
		node, existed := b.targets[id]
		if !existed {
			node = &TargetRefNode{
				ID:         id,
				Group:      group,
				Kind:       kind,
				Name:       ref.GetName(),
				Namespace:  ns,
				Resolution: res,
			}
			b.targets[id] = node
			b.g.TargetRefs = append(b.g.TargetRefs, *node)
		}
		b.g.Edges = append(b.g.Edges, Edge{
			From: policyID(e.ref),
			To:   id,
			Type: EdgeTargets,
		})
		// Record per-reference metadata on a side index used by diagnostics.
		b.refIndex[e.ref] = append(b.refIndex[e.ref], refIndexEntry{
			index:      i,
			nodeID:     id,
			ref:        ref,
			namespace:  ns,
			resolution: res,
		})
	}
}

// evaluateAttachments runs the pilot selection logic for every workload and emits
// applies-to, selects and binds edges.
func (b *builder) evaluateAttachments() {
	index := model.NewAuthorizationPolicies(b.in.RootNamespace, b.configs())

	for _, wl := range b.in.Workloads {
		wlRef := ObjectRef{Namespace: wl.Namespace, Name: wl.Name}
		wlID := workloadID(wlRef)

		b.g.Workloads = append(b.g.Workloads, WorkloadNode{
			ID:          wlID,
			Ref:         wlRef,
			Labels:      cloneSortedLabels(wl.Labels),
			Revision:    wl.Revision,
			IsWaypoint:  wl.IsWaypoint,
			GatewayName: wl.Labels[label.IoK8sNetworkingGatewayGatewayName.Name],
			Services:    wl.Services,
		})

		// A waypoint is authorized once per backing service (each service gets its own
		// policy evaluation), while Gateway/GatewayClass attached policies bind
		// independently of any service. Evaluate the service-less matcher plus one
		// matcher per service and take the union, mirroring the serving-side ECDS and
		// listener computations. ListAuthorizationPolicies accepts at most one service.
		baseMatcher := model.WorkloadPolicyMatcher{
			WorkloadNamespace: wl.Namespace,
			WorkloadLabels:    wl.Labels,
			IsWaypoint:        wl.IsWaypoint,
			RootNamespace:     b.in.RootNamespace,
		}
		matchers := []model.WorkloadPolicyMatcher{baseMatcher}
		for _, svc := range wl.Services {
			m := baseMatcher
			m.Services = []model.ServiceInfoForPolicyMatcher{svc}
			matchers = append(matchers, m)
		}

		seen := map[types.NamespacedName]bool{}
		var applied []model.AuthorizationPolicy
		for _, matcher := range matchers {
			result := index.ListAuthorizationPolicies(matcher)
			groups := [][]model.AuthorizationPolicy{result.Custom, result.Deny, result.Allow, result.Audit}
			for _, grp := range groups {
				for _, ap := range grp {
					key := ap.NamespacedName()
					if seen[key] {
						continue
					}
					seen[key] = true
					applied = append(applied, ap)
				}
			}
		}

		for _, ap := range applied {
			key := types.NamespacedName{Namespace: ap.Namespace, Name: ap.Name}
			e := b.byKey[key]
			if e == nil {
				continue
			}
			// Revision visibility: a pinned policy is only present for its own revision;
			// unpinned policies are visible to every revision.
			if !config.LabelsInRevision(e.cfg.Labels, wl.Revision) {
				continue
			}
			b.g.Edges = append(b.g.Edges, Edge{
				From:   policyID(e.ref),
				To:     wlID,
				Type:   EdgeAppliesTo,
				Action: actionName(ap.Spec.GetAction()),
			})

			refs := model.GetTargetRefs(ap.Spec)
			if len(refs) == 0 {
				b.g.Edges = append(b.g.Edges, Edge{
					From: selectorID(e.ref),
					To:   wlID,
					Type: EdgeSelects,
				})
			} else {
				for _, ref := range refs {
					if b.refBinds(e, ref, wl) {
						group, kind, _ := classifyTargetRef(ref)
						ns := ref.GetNamespace()
						if ns == "" {
							ns = e.ref.Namespace
						}
						b.g.Edges = append(b.g.Edges, Edge{
							From: targetID(group, kind, ns, ref.GetName()),
							To:   wlID,
							Type: EdgeBinds,
						})
					}
				}
			}
		}

		b.recordRelations(wl, wlID, applied)
	}
}

// refBinds mirrors the targetRef branches of model.WorkloadPolicyMatcher.ShouldAttachPolicy
// so that binds edges never diverge from the serving-time attachment decision.
func (b *builder) refBinds(e *policyEntry, ref *selectorpb.PolicyTargetReference, wl Workload) bool {
	// Service attached (waypoints only).
	if wl.IsWaypoint && canonicalGroupKind(ref, gvk.Service) {
		for _, svc := range wl.Services {
			if ref.GetName() == svc.Name && e.ref.Namespace == svc.Namespace && svc.Registry == provider.Kubernetes {
				return true
			}
		}
	}
	// ServiceEntry attached (waypoints only).
	if wl.IsWaypoint && canonicalGroupKind(ref, gvk.ServiceEntry) {
		for _, svc := range wl.Services {
			if ref.GetName() == svc.Name && e.ref.Namespace == svc.Namespace && svc.Registry == provider.External {
				return true
			}
		}
	}
	// Default waypoint policy attached via GatewayClass in the root namespace.
	if e.ref.Namespace == b.in.RootNamespace &&
		wl.IsWaypoint &&
		canonicalGroupKind(ref, gvk.GatewayClass) &&
		ref.GetName() == constants.WaypointGatewayClassName {
		return true
	}

	// Namespaced gateway attachment requires same namespace.
	if wl.Namespace != e.ref.Namespace {
		return false
	}
	if ref.GetNamespace() != "" && ref.GetNamespace() != wl.Namespace {
		return false
	}
	gwName := wl.Labels[label.IoK8sNetworkingGatewayGatewayName.Name]
	return gwName != "" && canonicalGroupKind(ref, gvk.KubernetesGateway) && ref.GetName() == gwName
}

// actionRank mirrors the authorization evaluation order: CUSTOM, then DENY, then ALLOW;
// AUDIT is independent of the allow/deny decision.
func actionRank(a string) int {
	switch a {
	case "CUSTOM":
		return 0
	case "DENY":
		return 1
	case "ALLOW":
		return 2
	case "AUDIT":
		return 3
	default:
		return 4
	}
}

func (b *builder) recordRelations(wl Workload, wlID string, applied []model.AuthorizationPolicy) {
	// Revision-visible policies only.
	visible := make([]model.AuthorizationPolicy, 0, len(applied))
	for _, ap := range applied {
		e := b.byKey[types.NamespacedName{Namespace: ap.Namespace, Name: ap.Name}]
		if e == nil || !config.LabelsInRevision(e.cfg.Labels, wl.Revision) {
			continue
		}
		visible = append(visible, ap)
	}
	for i := 0; i < len(visible); i++ {
		for j := i + 1; j < len(visible); j++ {
			a, bb := visible[i], visible[j]
			actA := actionName(a.Spec.GetAction())
			actB := actionName(bb.Spec.GetAction())
			idA := policyID(ObjectRef{Namespace: a.Namespace, Name: a.Name})
			idB := policyID(ObjectRef{Namespace: bb.Namespace, Name: bb.Name})

			from, to := idA, idB
			typ, reason := pairRelation(actA, actB)
			if actionRank(actB) < actionRank(actA) || (actionRank(actA) == actionRank(actB) && idB < idA) {
				from, to = idB, idA
			}
			key := from + "->" + to + "/" + typ
			r, ok := b.relations[key]
			if !ok {
				r = &relation{
					from:          from,
					to:            to,
					typ:           typ,
					reason:        reason,
					seenWorkloads: map[string]bool{},
				}
				b.relations[key] = r
			}
			if !r.seenWorkloads[wlID] {
				r.seenWorkloads[wlID] = true
				r.workloads = append(r.workloads, wlID)
			}
		}
	}
}

func pairRelation(a, b2 string) (typ, reason string) {
	if a == b2 {
		return EdgeCombines, ReasonSameActionOR
	}
	lo, hi := a, b2
	if actionRank(lo) > actionRank(hi) {
		lo, hi = hi, lo
	}
	switch {
	case lo == "CUSTOM":
		return EdgeOverrides, ReasonCustomFirst
	case lo == "DENY" && hi == "ALLOW":
		return EdgeOverrides, ReasonDenyPrecedence
	case lo == "DENY" && hi == "AUDIT":
		return EdgeRelates, ReasonDenyAndAudit
	case lo == "ALLOW" && hi == "AUDIT":
		return EdgeRelates, ReasonAllowAndAudit
	}
	return EdgeRelates, lo + "-" + hi
}

func (b *builder) emitRelations() {
	for _, r := range b.relations {
		sort.Strings(r.workloads)
		b.g.Edges = append(b.g.Edges, Edge{
			From:      r.from,
			To:        r.to,
			Type:      r.typ,
			Reason:    r.reason,
			Workloads: r.workloads,
		})
	}
}

func (b *builder) configs() []config.Config {
	out := make([]config.Config, 0, len(b.policies))
	for _, e := range b.policies {
		out = append(out, e.cfg)
	}
	return out
}

// classifyTargetRef maps a targetRef to its canonical group and graph resolution kind.
// Mirrors the kinds accepted by model.WorkloadPolicyMatcher.ShouldAttachPolicy and the
// HTTPRoute index in model.AuthorizationPolicies.
func classifyTargetRef(ref *selectorpb.PolicyTargetReference) (group, kind, resolution string) {
	group = config.CanonicalGroup(ref.GetGroup())
	kind = ref.GetKind()
	switch {
	case canonicalGroupKindValue(group, kind, gvk.Service):
		return group, kind, ResolutionService
	case canonicalGroupKindValue(group, kind, gvk.ServiceEntry):
		return group, kind, ResolutionServiceEntry
	case canonicalGroupKindValue(group, kind, gvk.KubernetesGateway):
		return group, kind, ResolutionGateway
	case canonicalGroupKindValue(group, kind, gvk.GatewayClass):
		return group, kind, ResolutionGatewayClass
	case features.EnableGatewayAPIHTTPRouteAuth && canonicalGroupKindValue(group, kind, gvk.HTTPRoute):
		return group, kind, ResolutionHTTPRoute
	default:
		return group, kind, ResolutionUnsupported
	}
}

func canonicalGroupKind(ref *selectorpb.PolicyTargetReference, g config.GroupVersionKind) bool {
	return canonicalGroupKindValue(config.CanonicalGroup(ref.GetGroup()), ref.GetKind(), g)
}

func canonicalGroupKindValue(group, kind string, g config.GroupVersionKind) bool {
	return group == g.CanonicalGroup() && kind == g.Kind
}

func itoa(i int) string {
	const digits = "0123456789"
	if i == 0 {
		return "0"
	}
	neg := i < 0
	if neg {
		i = -i
	}
	var b [24]byte
	pos := len(b)
	for i > 0 {
		pos--
		b[pos] = digits[i%10]
		i /= 10
	}
	if neg {
		pos--
		b[pos] = '-'
	}
	return string(b[pos:])
}
