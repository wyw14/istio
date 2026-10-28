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

package model

import (
	"sort"
	"sync"
	"sync/atomic"

	"istio.io/istio/pkg/cluster"
)

// ResourceType identifies the xDS resource kind of a generated Envoy object.
type ResourceType string

const (
	// ListenerResource is an Envoy listener produced by LDS.
	ListenerResource ResourceType = "listener"
	// ClusterResource is an Envoy cluster produced by CDS.
	ClusterResource ResourceType = "cluster"
	// RouteResource is an Envoy route configuration produced by RDS.
	RouteResource ResourceType = "route"
)

// SourceKind identifies where a generated resource originates.
type SourceKind string

const (
	// SourceService means the resource is derived from a Kubernetes Service or ServiceEntry.
	SourceService SourceKind = "Service"
	// SourceVirtualService means the resource is derived from a VirtualService.
	SourceVirtualService SourceKind = "VirtualService"
	// SourceGateway means the resource is derived from a Gateway.
	SourceGateway SourceKind = "Gateway"
	// SourceDefault means the resource is synthesized by Istio defaults rather than user config.
	SourceDefault SourceKind = "default"
)

// ResourceSource records a single configuration object that contributes to a generated
// Envoy resource. A single Envoy resource (for example a gateway listener) may be backed
// by several sources.
type ResourceSource struct {
	// Kind is the category of the originating object.
	Kind SourceKind `json:"kind"`
	// Name is the name of the originating object (service FQDN for services, object name otherwise).
	Name string `json:"name"`
	// Namespace is the namespace of the originating object, empty for defaults.
	Namespace string `json:"namespace,omitempty"`
	// Version is the opaque resource version of the originating object, empty for defaults.
	Version string `json:"version,omitempty"`
	// Cluster is the cluster the originating object lives in, relevant in multi-cluster meshes.
	Cluster cluster.ID `json:"cluster,omitempty"`
}

// ResourceRef identifies a generated Envoy resource.
type ResourceRef struct {
	// Type is the xDS resource type.
	Type ResourceType `json:"type"`
	// Name is the Envoy resource name.
	Name string `json:"name"`
}

// ProxyResourceSources maps every generated Envoy resource of a proxy to the configuration
// objects that produced it. It is the read-only view served to consumers; callers MUST NOT
// mutate maps returned by the index.
type ProxyResourceSources map[ResourceRef][]ResourceSource

// ResourceEntries maps generated resource names of one xDS type to their sources. The builder
// constructs a fresh map for every generation; the index replaces the previous per-type map
// wholesale, which is what guarantees that removed resources and deleted configs do not linger.
type ResourceEntries map[string][]ResourceSource

// ResourceSourceLookup is the read-only view of the resource source index. It is intentionally
// limited to accessors so consumers (debug endpoints, istioctl) can never mutate generation
// state or trigger a push.
type ResourceSourceLookup interface {
	// Lookup returns the sources recorded for a single resource of a proxy.
	// The returned slice is a copy and may be freely used by the caller.
	Lookup(proxyID string, ref ResourceRef) ([]ResourceSource, bool)
	// Snapshot returns the merged, read-only source snapshot for a proxy and the per-proxy
	// version at which it was last updated. The returned map MUST NOT be mutated.
	Snapshot(proxyID string) (ProxyResourceSources, uint64, bool)
	// ProxyIDs returns the proxy IDs for which sources are recorded, sorted.
	ProxyIDs() []string
	// Version returns the monotonically increasing global index version. It is bumped every
	// time a per-proxy/per-type map is replaced, allowing callers to detect incremental changes.
	Version() uint64
}

// proxySources stores the sources of one proxy, separated by xDS type so that e.g. an
// incremental CDS push can replace the cluster map without discarding listener/route data.
type proxySources struct {
	// types maps ResourceType -> resource name -> sources. Each inner map is replaced, never
	// mutated in place, so the read side can serve maps without copying.
	types   map[ResourceType]ResourceEntries
	version uint64
}

// ResourceSourceIndex records, per proxy, the configuration sources (Service, VirtualService,
// Gateway or synthesized defaults) of generated listener/cluster/route resources.
//
// The index is populated as a read-only side effect of config generation. It never enqueues
// pushes or feeds back into push decisions. Each generation replaces the per-type map for the
// proxy atomically, so deleting a configuration object (or the resource it produced) can never
// leave a stale source: the next generation builds a fresh map that simply does not contain it.
type ResourceSourceIndex struct {
	mu      sync.RWMutex
	proxies map[string]*proxySources
	version atomic.Uint64
}

// NewResourceSourceIndex creates an empty ResourceSourceIndex.
func NewResourceSourceIndex() *ResourceSourceIndex {
	return &ResourceSourceIndex{
		proxies: map[string]*proxySources{},
	}
}

var _ ResourceSourceLookup = &ResourceSourceIndex{}

// Record replaces the source entries of one xDS type for a proxy and returns the new global
// index version. The whole per-type map is replaced rather than merged, so resources that
// disappeared from generation and sources whose config was deleted are not retained. entries
// must not be mutated after this call.
func (i *ResourceSourceIndex) Record(proxyID string, rtype ResourceType, entries ResourceEntries) uint64 {
	if i == nil {
		return 0
	}
	if entries == nil {
		entries = ResourceEntries{}
	}
	version := i.version.Add(1)
	i.mu.Lock()
	ps, ok := i.proxies[proxyID]
	if !ok {
		ps = &proxySources{types: map[ResourceType]ResourceEntries{}}
		i.proxies[proxyID] = ps
	}
	ps.types[rtype] = entries
	ps.version = version
	i.mu.Unlock()
	return version
}

// RemoveProxy drops all sources recorded for a proxy, for example when it disconnects.
func (i *ResourceSourceIndex) RemoveProxy(proxyID string) {
	if i == nil {
		return
	}
	i.mu.Lock()
	delete(i.proxies, proxyID)
	i.mu.Unlock()
}

// RecordDelta applies an incremental generation to one xDS type of a proxy: it sets the sources
// of updated resources and drops removed resources, while leaving sources of unchanged
// resources intact. It returns the new global index version. As with Record, the result is a
// freshly built map, so removed resources never linger. updated must not be mutated after this
// call.
func (i *ResourceSourceIndex) RecordDelta(proxyID string, rtype ResourceType, updated ResourceEntries, removed []string) uint64 {
	if i == nil {
		return 0
	}
	version := i.version.Add(1)
	i.mu.Lock()
	ps, ok := i.proxies[proxyID]
	if !ok {
		ps = &proxySources{types: map[ResourceType]ResourceEntries{}}
		i.proxies[proxyID] = ps
	}
	merged := make(ResourceEntries, len(ps.types[rtype])+len(updated))
	for name, sources := range ps.types[rtype] {
		merged[name] = sources
	}
	for name, sources := range updated {
		merged[name] = sources
	}
	for _, name := range removed {
		delete(merged, name)
	}
	ps.types[rtype] = merged
	ps.version = version
	i.mu.Unlock()
	return version
}

// Lookup implements ResourceSourceLookup.
func (i *ResourceSourceIndex) Lookup(proxyID string, ref ResourceRef) ([]ResourceSource, bool) {
	if i == nil {
		return nil, false
	}
	i.mu.RLock()
	defer i.mu.RUnlock()
	ps, ok := i.proxies[proxyID]
	if !ok {
		return nil, false
	}
	sources, ok := ps.types[ref.Type][ref.Name]
	if !ok {
		return nil, false
	}
	out := make([]ResourceSource, len(sources))
	copy(out, sources)
	return out, true
}

// Snapshot implements ResourceSourceLookup by merging all per-type maps of the proxy. The
// returned map is freshly allocated and may be read freely; the source slices inside are
// shared and immutable.
func (i *ResourceSourceIndex) Snapshot(proxyID string) (ProxyResourceSources, uint64, bool) {
	if i == nil {
		return nil, 0, false
	}
	i.mu.RLock()
	defer i.mu.RUnlock()
	ps, ok := i.proxies[proxyID]
	if !ok {
		return nil, 0, false
	}
	total := 0
	for _, m := range ps.types {
		total += len(m)
	}
	out := make(ProxyResourceSources, total)
	for rtype, m := range ps.types {
		for name, sources := range m {
			out[ResourceRef{Type: rtype, Name: name}] = sources
		}
	}
	return out, ps.version, true
}

// ProxyIDs implements ResourceSourceLookup.
func (i *ResourceSourceIndex) ProxyIDs() []string {
	if i == nil {
		return nil
	}
	i.mu.RLock()
	ids := make([]string, 0, len(i.proxies))
	for id := range i.proxies {
		ids = append(ids, id)
	}
	i.mu.RUnlock()
	sort.Strings(ids)
	return ids
}

// Version implements ResourceSourceLookup.
func (i *ResourceSourceIndex) Version() uint64 {
	if i == nil {
		return 0
	}
	return i.version.Load()
}

// SortSources returns a deterministic, deduplicated copy of sources ordered by Kind, Namespace,
// Name and Version. Builders use it to keep snapshots stable across regenerations.
func SortSources(in []ResourceSource) []ResourceSource {
	if len(in) == 0 {
		return nil
	}
	type key struct {
		k, n, ns, v string
		c           cluster.ID
	}
	seen := make(map[key]struct{}, len(in))
	out := make([]ResourceSource, 0, len(in))
	for _, s := range in {
		k := key{string(s.Kind), s.Name, s.Namespace, s.Version, s.Cluster}
		if _, ok := seen[k]; ok {
			continue
		}
		seen[k] = struct{}{}
		out = append(out, s)
	}
	sort.Slice(out, func(a, b int) bool {
		if out[a].Kind != out[b].Kind {
			return out[a].Kind < out[b].Kind
		}
		if out[a].Namespace != out[b].Namespace {
			return out[a].Namespace < out[b].Namespace
		}
		if out[a].Name != out[b].Name {
			return out[a].Name < out[b].Name
		}
		return out[a].Version < out[b].Version
	})
	return out
}
