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
	"fmt"
	"sort"

	"google.golang.org/protobuf/reflect/protoreflect"
	"k8s.io/apimachinery/pkg/types"

	"istio.io/api/security/v1beta1"
	selectorpb "istio.io/api/type/v1beta1"
	"istio.io/istio/pilot/pkg/model"
	authzmodel "istio.io/istio/pilot/pkg/security/authz/model"
)

// Diagnostic codes. Cross-namespace references and unknown fields are always reported
// under distinct codes so consumers can route them separately.
const (
	// SeverityInfo/Warning/Error mirror common diagnostic severities.
	SeverityInfo    = "info"
	SeverityWarning = "warning"
	SeverityError   = "error"

	// CodeCrossNamespaceTargetRef is reported when a targetRef explicitly points at
	// another namespace; Istio never binds such references.
	CodeCrossNamespaceTargetRef = "AUTHZ_GRAPH_CROSS_NS_TARGET_REF"
	// CodeGatewayClassNotInRootNamespace is reported when a GatewayClass targetRef is
	// used by a policy outside the mesh root namespace.
	CodeGatewayClassNotInRootNamespace = "AUTHZ_GRAPH_GATEWAYCLASS_NOT_ROOT_NS"
	// CodeUnsupportedTargetKind is reported when a targetRef group/kind is not attachable.
	CodeUnsupportedTargetKind = "AUTHZ_GRAPH_UNSUPPORTED_TARGET_KIND"
	// CodeUnresolvedTargetRef is reported when a targetRef does not resolve to an
	// object present in the graph inputs.
	CodeUnresolvedTargetRef = "AUTHZ_GRAPH_UNRESOLVED_TARGET_REF"
	// CodeTargetBindsNoWorkload is reported when the targetRef resolves but no
	// workload in the graph binds to it (e.g. a Service targetRef without a waypoint).
	CodeTargetBindsNoWorkload = "AUTHZ_GRAPH_TARGET_BINDS_NO_WORKLOAD"
	// CodeUnknownField is reported for spec fields that are not part of the
	// AuthorizationPolicy schema and were dropped during decoding.
	CodeUnknownField = "AUTHZ_GRAPH_UNKNOWN_FIELD"
	// CodeUnsupportedConditionAttribute is reported for a "when" key that the
	// authorization model cannot compile.
	CodeUnsupportedConditionAttribute = "AUTHZ_GRAPH_UNSUPPORTED_CONDITION"
	// CodePinTargetRefRevision recommends pinning targetRef policies to a revision in
	// multi-revision meshes.
	CodePinTargetRefRevision = "AUTHZ_GRAPH_PIN_TARGETREF_REVISION"
	// CodeInternalTypeError is reported for malformed graph inputs.
	CodeInternalTypeError = "AUTHZ_GRAPH_INTERNAL_TYPE_ERROR"
)

// Diagnostic describes a single graph finding. Diagnostics never affect authorization
// computation; they only describe what was (or could not be) observed.
type Diagnostic struct {
	Code      string     `json:"code"`
	Severity  string     `json:"severity"`
	Resource  *ObjectRef `json:"resource,omitempty"`
	FieldPath string     `json:"fieldPath,omitempty"`
	Message   string     `json:"message"`
}

func (b *builder) diagnose() {
	multiRevision := len(b.g.Mesh.Revisions) > 1

	for _, e := range b.policies {
		b.diagnoseUnknownFields(e)
		b.diagnoseRules(e)
		b.diagnoseTargetRefs(e)
		if multiRevision && len(model.GetTargetRefs(e.spec)) > 0 && e.cfg.Labels[revLabel] == "" {
			b.g.Diagnostics = append(b.g.Diagnostics, Diagnostic{
				Code:      CodePinTargetRefRevision,
				Severity:  SeverityInfo,
				Resource:  &e.ref,
				FieldPath: "metadata.labels.istio.io/rev",
				Message:   "targetRef policy in a multi-revision mesh should be pinned to a revision with the istio.io/rev label so older control planes do not interpret it as namespace-wide",
			})
		}
	}

	b.resolveTargetNodes()
}

func (b *builder) diagnoseUnknownFields(e *policyEntry) {
	if e.raw == nil {
		return
	}
	for _, fieldPath := range findUnknownSpecFields(e.raw) {
		b.g.Diagnostics = append(b.g.Diagnostics, Diagnostic{
			Code:      CodeUnknownField,
			Severity:  SeverityWarning,
			Resource:  &e.ref,
			FieldPath: fieldPath,
			Message:   fmt.Sprintf("unknown field %s is not part of the AuthorizationPolicy schema and is ignored", fieldPath),
		})
	}
}

func (b *builder) diagnoseRules(e *policyEntry) {
	for ri, rule := range e.spec.GetRules() {
		// Compile the rule with the same parser used to build Envoy RBAC. This exercises
		// no authorization decision; it only reveals attributes the engine does not know.
		if _, err := authzmodel.New(types.NamespacedName{Namespace: e.ref.Namespace, Name: e.ref.Name}, rule); err != nil {
			b.g.Diagnostics = append(b.g.Diagnostics, Diagnostic{
				Code:      CodeUnsupportedConditionAttribute,
				Severity:  SeverityWarning,
				Resource:  &e.ref,
				FieldPath: fmt.Sprintf("spec.rules[%d].when", ri),
				Message:   err.Error(),
			})
		}
	}
}

func (b *builder) diagnoseTargetRefs(e *policyEntry) {
	for _, ri := range b.refIndex[e.ref] {
		ref := ri.ref
		fieldPath := fmt.Sprintf("spec.targetRefs[%d]", ri.index)
		if ri.index == 0 && e.spec.GetTargetRef() != nil && len(e.spec.GetTargetRefs()) == 0 {
			fieldPath = "spec.targetRef"
		}

		// Cross-namespace references to namespaced kinds are never bound.
		if ri.resolution != ResolutionUnsupported &&
			ri.resolution != ResolutionGatewayClass &&
			ref.GetNamespace() != "" && ref.GetNamespace() != e.ref.Namespace {
			b.g.Diagnostics = append(b.g.Diagnostics, Diagnostic{
				Code:      CodeCrossNamespaceTargetRef,
				Severity:  SeverityWarning,
				Resource:  &e.ref,
				FieldPath: fieldPath + ".namespace",
				Message: fmt.Sprintf("targetRef %s %s.%s is in namespace %s but cross-namespace references are not supported; the policy will never bind",
					ref.GetKind(), ri.namespace, ref.GetName(), ref.GetNamespace()),
			})
		}

		switch ri.resolution {
		case ResolutionUnsupported:
			b.g.Diagnostics = append(b.g.Diagnostics, Diagnostic{
				Code:      CodeUnsupportedTargetKind,
				Severity:  SeverityWarning,
				Resource:  &e.ref,
				FieldPath: fieldPath,
				Message: fmt.Sprintf("targetRef %s.%s/%s is not an attachable kind for AuthorizationPolicy",
					ref.GetGroup(), ref.GetKind(), ref.GetName()),
			})
		case ResolutionGatewayClass:
			if e.ref.Namespace != b.in.RootNamespace {
				b.g.Diagnostics = append(b.g.Diagnostics, Diagnostic{
					Code:      CodeGatewayClassNotInRootNamespace,
					Severity:  SeverityWarning,
					Resource:  &e.ref,
					FieldPath: fieldPath,
					Message: fmt.Sprintf("GatewayClass targetRef is only honored for policies in the root namespace %q, policy is in %q",
						b.in.RootNamespace, e.ref.Namespace),
				})
			}
			if !b.gatewayClassExists(ref.GetName()) {
				b.unresolvedDiagnostic(e, fieldPath, ref)
			}
		case ResolutionService:
			if !b.serviceExists(ri.namespace, ref.GetName(), providerKubernetes) {
				b.unresolvedDiagnostic(e, fieldPath, ref)
			}
		case ResolutionServiceEntry:
			if !b.serviceExists(ri.namespace, ref.GetName(), providerExternal) {
				b.unresolvedDiagnostic(e, fieldPath, ref)
			}
		case ResolutionGateway:
			if !b.gatewayExists(ri.namespace, ref.GetName()) {
				b.unresolvedDiagnostic(e, fieldPath, ref)
			}
		case ResolutionHTTPRoute:
			if !b.httpRouteExists(ri.namespace, ref.GetName()) {
				b.unresolvedDiagnostic(e, fieldPath, ref)
			}
		}
	}
}

func (b *builder) unresolvedDiagnostic(e *policyEntry, fieldPath string, ref *selectorpb.PolicyTargetReference) {
	b.g.Diagnostics = append(b.g.Diagnostics, Diagnostic{
		Code:      CodeUnresolvedTargetRef,
		Severity:  SeverityInfo,
		Resource:  &e.ref,
		FieldPath: fieldPath,
		Message: fmt.Sprintf("targetRef %s %s.%s does not resolve to an existing object",
			ref.GetKind(), effectiveNamespace(ref, e.ref.Namespace), ref.GetName()),
	})
}

// resolveTargetNodes marks target resolution and flags targets that bind to no
// workload in the graph.
func (b *builder) resolveTargetNodes() {
	bound := map[string]bool{}
	for _, ed := range b.g.Edges {
		if ed.Type == EdgeBinds {
			bound[ed.From] = true
		}
	}
	for i := range b.g.TargetRefs {
		t := &b.g.TargetRefs[i]
		switch t.Resolution {
		case ResolutionService:
			t.Resolved = b.serviceExists(t.Namespace, t.Name, providerKubernetes)
		case ResolutionServiceEntry:
			t.Resolved = b.serviceExists(t.Namespace, t.Name, providerExternal)
		case ResolutionGateway:
			t.Resolved = b.gatewayExists(t.Namespace, t.Name)
		case ResolutionGatewayClass:
			t.Resolved = b.gatewayClassExists(t.Name)
		case ResolutionHTTPRoute:
			t.Resolved = b.httpRouteExists(t.Namespace, t.Name)
		}
		if t.Resolution != ResolutionUnsupported && t.Resolved && !bound[t.ID] {
			if ref, idx, ok := b.policyReferencingTarget(t.ID); ok {
				b.g.Diagnostics = append(b.g.Diagnostics, Diagnostic{
					Code:      CodeTargetBindsNoWorkload,
					Severity:  SeverityInfo,
					Resource:  &ref,
					FieldPath: fmt.Sprintf("spec.targetRefs[%d]", idx),
					Message: fmt.Sprintf("%s %s.%s exists but no workload in the graph binds to it (Service/ServiceEntry targets require a waypoint in the same namespace)",
						t.Kind, t.Namespace, t.Name),
				})
			}
		}
	}
}

func (b *builder) policyReferencingTarget(id string) (ObjectRef, int, bool) {
	for ref, entries := range b.refIndex {
		for _, ri := range entries {
			if ri.nodeID == id {
				return ref, ri.index, true
			}
		}
	}
	return ObjectRef{}, -1, false
}

func effectiveNamespace(ref *selectorpb.PolicyTargetReference, policyNamespace string) string {
	if ns := ref.GetNamespace(); ns != "" {
		return ns
	}
	return policyNamespace
}

// findUnknownSpecFields walks the raw decoded object against the AuthorizationPolicy
// protobuf descriptor and returns the JSON paths of fields the schema does not declare.
func findUnknownSpecFields(raw map[string]any) []string {
	spec, ok := raw["spec"].(map[string]any)
	if !ok {
		return nil
	}
	descriptor := (&v1beta1.AuthorizationPolicy{}).ProtoReflect().Descriptor()
	return walkMessage(descriptor, spec, "spec")
}

func walkMessage(md protoreflect.MessageDescriptor, v any, path string) []string {
	m, ok := v.(map[string]any)
	if !ok {
		return nil
	}
	var out []string
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		fd := fieldByJSONOrName(md, k)
		if fd == nil {
			out = append(out, path+"."+k)
			continue
		}
		if fd.Kind() != protoreflect.MessageKind {
			continue
		}
		// Map fields (e.g. selector.matchLabels) have arbitrary user-provided keys;
		// their entries are synthetic messages, so do not recurse into them.
		if fd.IsMap() {
			continue
		}
		switch {
		case fd.IsList():
			arr, ok := m[k].([]any)
			if !ok {
				continue
			}
			for i, el := range arr {
				out = append(out, walkMessage(fd.Message(), el, fmt.Sprintf("%s.%s[%d]", path, k, i))...)
			}
		default:
			out = append(out, walkMessage(fd.Message(), m[k], path+"."+k)...)
		}
	}
	return out
}

func fieldByJSONOrName(md protoreflect.MessageDescriptor, name string) protoreflect.FieldDescriptor {
	fields := md.Fields()
	for i := 0; i < fields.Len(); i++ {
		fd := fields.Get(i)
		if string(fd.JSONName()) == name || string(fd.TextName()) == name || string(fd.Name()) == name {
			return fd
		}
	}
	return nil
}

// sort makes every emitted slice deterministic, giving consumers stable JSON output.
func (b *builder) sort() {
	sort.Slice(b.g.Policies, func(i, j int) bool { return b.g.Policies[i].ID < b.g.Policies[j].ID })
	sort.Slice(b.g.Workloads, func(i, j int) bool { return b.g.Workloads[i].ID < b.g.Workloads[j].ID })
	sort.Slice(b.g.Selectors, func(i, j int) bool { return b.g.Selectors[i].ID < b.g.Selectors[j].ID })
	sort.Slice(b.g.Operations, func(i, j int) bool { return b.g.Operations[i].ID < b.g.Operations[j].ID })
	sort.Slice(b.g.TargetRefs, func(i, j int) bool { return b.g.TargetRefs[i].ID < b.g.TargetRefs[j].ID })
	sort.Slice(b.g.Edges, func(i, j int) bool {
		if b.g.Edges[i].From != b.g.Edges[j].From {
			return b.g.Edges[i].From < b.g.Edges[j].From
		}
		if b.g.Edges[i].To != b.g.Edges[j].To {
			return b.g.Edges[i].To < b.g.Edges[j].To
		}
		return b.g.Edges[i].Type < b.g.Edges[j].Type
	})
	for i := range b.g.Edges {
		if len(b.g.Edges[i].Workloads) > 1 {
			sort.Strings(b.g.Edges[i].Workloads)
		}
	}
	sort.Slice(b.g.Diagnostics, func(i, j int) bool {
		x, y := b.g.Diagnostics[i], b.g.Diagnostics[j]
		if x.Code != y.Code {
			return x.Code < y.Code
		}
		xr, yr := refString(x.Resource), refString(y.Resource)
		if xr != yr {
			return xr < yr
		}
		if x.FieldPath != y.FieldPath {
			return x.FieldPath < y.FieldPath
		}
		return x.Message < y.Message
	})
}

func refString(r *ObjectRef) string {
	if r == nil {
		return ""
	}
	return r.Namespace + "/" + r.Name
}
