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

package xds

import (
	"net/http"
	"sort"
	"strconv"
	"strings"

	networking "istio.io/api/networking/v1alpha3"

	"istio.io/istio/pilot/pkg/model"
	"istio.io/istio/pilot/pkg/networking/util"
	v3 "istio.io/istio/pilot/pkg/xds/v3"
	"istio.io/istio/pkg/cluster"
	"istio.io/istio/pkg/config"
	"istio.io/istio/pkg/config/host"
	"istio.io/istio/pkg/config/schema/gvk"
)

// resourceSourceIndexTypeURL maps an xDS type URL to the resource type tracked in the index.
var resourceSourceIndexTypeURL = map[string]model.ResourceType{
	v3.ClusterType:  model.ClusterResource,
	v3.ListenerType: model.ListenerResource,
	v3.RouteType:    model.RouteResource,
}

// recordResourceSources derives the configuration sources (Service/VirtualService/Gateway or
// synthesized defaults) of the generated resources and records them in the read-only index.
//
// This is a pure observation step: it only writes to s.SourceIndex and never enqueues a push or
// mutates the push context. It is invoked after LDS/CDS/RDS generation on the SOTW path, so
// the per-type snapshot always reflects the resources actually sent.
func (s *DiscoveryServer) recordResourceSources(proxy *model.Proxy, push *model.PushContext, rtype model.ResourceType, resources model.Resources) {
	if s.SourceIndex == nil || proxy == nil || push == nil {
		return
	}
	s.SourceIndex.Record(proxy.ID, rtype, s.buildResourceEntries(proxy, rtype, resources))
}

// recordResourceSourcesDelta applies an incremental generation: updated resources refresh
// their sources and removed resources are dropped from the index. Used on the delta xDS path.
func (s *DiscoveryServer) recordResourceSourcesDelta(proxy *model.Proxy, push *model.PushContext, rtype model.ResourceType,
	updated model.Resources, removed []string,
) {
	if s.SourceIndex == nil || proxy == nil || push == nil {
		return
	}
	s.SourceIndex.RecordDelta(proxy.ID, rtype, s.buildResourceEntries(proxy, rtype, updated), removed)
}

// buildResourceEntries attributes every generated resource by name. The Envoy resource body is
// not needed: listener/cluster/route names are self-describing and the proxy/push context
// supplies the originating configs.
func (s *DiscoveryServer) buildResourceEntries(proxy *model.Proxy, rtype model.ResourceType, resources model.Resources) model.ResourceEntries {
	b := sourceBuilder{server: s, proxy: proxy}
	entries := make(model.ResourceEntries, len(resources))
	for _, r := range resources {
		if r == nil || r.Name == "" {
			continue
		}
		entries[r.Name] = model.SortSources(b.sources(rtype, r.Name))
	}
	return entries
}

type sourceBuilder struct {
	server *DiscoveryServer
	proxy  *model.Proxy
}

func (b *sourceBuilder) sources(rtype model.ResourceType, name string) []model.ResourceSource {
	switch rtype {
	case model.ClusterResource:
		return b.clusterSources(name)
	case model.ListenerResource:
		return b.listenerSources(name)
	case model.RouteResource:
		return b.routeSources(name)
	default:
		return nil
	}
}

func (b *sourceBuilder) clusterID() cluster.ID {
	if b.proxy != nil && b.proxy.Metadata != nil {
		return b.proxy.Metadata.ClusterID
	}
	return ""
}

func (b *sourceBuilder) defaultSource() []model.ResourceSource {
	return []model.ResourceSource{{Kind: model.SourceDefault, Name: "default", Cluster: b.clusterID()}}
}

func (b *sourceBuilder) serviceSource(svc *model.Service) model.ResourceSource {
	return model.ResourceSource{
		Kind:      model.SourceService,
		Name:      string(svc.Hostname),
		Namespace: svc.Attributes.Namespace,
		Version:   svc.ResourceVersion,
		Cluster:   b.clusterID(),
	}
}

func (b *sourceBuilder) virtualServiceSource(cfg *config.Config) model.ResourceSource {
	return model.ResourceSource{
		Kind:      model.SourceVirtualService,
		Name:      cfg.Name,
		Namespace: cfg.Namespace,
		Version:   cfg.ResourceVersion,
		Cluster:   b.clusterID(),
	}
}

// serviceByHostname resolves a hostname against the proxy's sidecar scope, so sidecar import
// filters and exportTo are honored. Gateway scopes include the services exported to their
// namespace as well.
func (b *sourceBuilder) serviceByHostname(hostname host.Name) *model.Service {
	if b.proxy == nil || b.proxy.SidecarScope == nil {
		return nil
	}
	return b.proxy.SidecarScope.GetService(hostname)
}

// infraClusters are synthesized by Istio/Envoy bootstrap rather than derived from a user
// configuration object.
var infraClusters = map[string]struct{}{
	util.BlackHoleCluster:          {},
	util.PassthroughCluster:        {},
	util.InboundPassthroughCluster: {},
	util.AllowAnyDynamicDNSCluster: {},
	util.SelfDiscoveryCluster:      {},
	"xds-grpc":                     {},
	"sds-grpc":                     {},
	"prometheus_stats":             {},
	"agent":                        {},
	"agent_read_config":            {},
	"otel_stats":                   {},
	"istio_telemetry_stats":        {},
}

func (b *sourceBuilder) clusterSources(name string) []model.ResourceSource {
	if _, infra := infraClusters[name]; infra {
		return b.defaultSource()
	}
	if !model.IsValidSubsetKey(name) {
		// SNI-DNAT DNS SRV keys and any other non-subset clusters are treated as defaults.
		return b.defaultSource()
	}
	_, _, hostname, _ := model.ParseSubsetKey(name)
	if hostname == "" {
		// Inbound passthrough clusters carry no destination hostname.
		return b.defaultSource()
	}
	if svc := b.serviceByHostname(hostname); svc != nil {
		return []model.ResourceSource{b.serviceSource(svc)}
	}
	return b.defaultSource()
}

// portFromListenerName extracts the port from names shaped like "<bind>_<port>".
func portFromListenerName(name string) (int, bool) {
	idx := strings.LastIndex(name, "_")
	if idx < 0 || idx == len(name)-1 {
		return 0, false
	}
	port, err := strconv.Atoi(name[idx+1:])
	if err != nil {
		return 0, false
	}
	return port, true
}

func (b *sourceBuilder) listenerSources(name string) []model.ResourceSource {
	switch name {
	case model.VirtualInboundListenerName, model.VirtualOutboundListenerName:
		return b.defaultSource()
	}
	port, ok := portFromListenerName(name)
	if !ok {
		return b.defaultSource()
	}
	if b.proxy.Type == model.Router {
		return b.gatewayPortSources(port)
	}
	return b.sidecarPortSources(port)
}

func (b *sourceBuilder) routeSources(name string) []model.ResourceSource {
	switch {
	case b.proxy.Type == model.Router:
		return b.gatewayRouteSources(name)
	default:
		// Sidecar route configurations are named for the listener port.
		port, err := strconv.Atoi(name)
		if err != nil {
			return b.defaultSource()
		}
		return b.sidecarPortSources(port)
	}
}

// sidecarPortSources attributes a sidecar listener/route on port to the services exposed on
// that port by the proxy's sidecar scope and the VirtualServices imported by the matching
// egress listener that actually shape routing for those services. When neither applies the
// resource is the synthesized allow-all/default behavior.
func (b *sourceBuilder) sidecarPortSources(port int) []model.ResourceSource {
	scope := b.proxy.SidecarScope
	if scope == nil {
		return b.defaultSource()
	}
	el := scope.GetEgressListenerForRDS(port, "")
	if el == nil {
		return b.defaultSource()
	}

	portHosts := setsHostName{}
	for _, svc := range el.Services() {
		if serviceHasPort(svc, port) {
			portHosts[svc.Hostname] = struct{}{}
		}
	}

	out := make([]model.ResourceSource, 0)
	addedService := map[host.Name]struct{}{}
	for h := range portHosts {
		if svc := b.serviceByHostname(h); svc != nil {
			if _, ok := addedService[svc.Hostname]; !ok {
				addedService[svc.Hostname] = struct{}{}
				out = append(out, b.serviceSource(svc))
			}
		}
	}

	// A VirtualService drives this port when one of its hosts is served on the port, either
	// directly or through a route destination.
	for _, cfg := range el.VirtualServices() {
		if cfg == nil {
			continue
		}
		if virtualServiceMatchesHosts(cfg, portHosts, port) {
			out = append(out, b.virtualServiceSource(cfg))
		}
	}

	if len(out) == 0 {
		return b.defaultSource()
	}
	return out
}

// gatewayPortSources attributes a gateway listener (or http.<port> route) to the Gateway
// servers bound to the port and the VirtualServices selected for those gateways.
func (b *sourceBuilder) gatewayPortSources(port int) []model.ResourceSource {
	mg := b.proxy.MergedGateway
	if mg == nil {
		return b.defaultSource()
	}
	gateways := b.gatewayOwnersOnPort(port)
	return b.gatewaySources(gateways)
}

// gatewayOwnersOnPort returns the distinct namespace/name gateways owning servers on port.
func (b *sourceBuilder) gatewayOwnersOnPort(port int) []string {
	mg := b.proxy.MergedGateway
	if mg == nil {
		return nil
	}
	owners := map[string]struct{}{}
	for sp, merged := range mg.MergedServers {
		if int(sp.Number) != port {
			continue
		}
		for _, srv := range merged.Servers {
			if owner := mg.GatewayNameForServer[srv]; owner != "" {
				owners[owner] = struct{}{}
			}
		}
	}
	out := make([]string, 0, len(owners))
	for g := range owners {
		out = append(out, g)
	}
	return out
}

func (b *sourceBuilder) gatewaySources(gateways []string) []model.ResourceSource {
	if len(gateways) == 0 {
		return b.defaultSource()
	}
	out := make([]model.ResourceSource, 0, len(gateways))
	seen := map[string]struct{}{}
	for _, gw := range gateways {
		if _, ok := seen[gw]; ok {
			continue
		}
		seen[gw] = struct{}{}
		if src, ok := b.gatewaySource(gw); ok {
			out = append(out, src)
		}
		for _, vs := range b.virtualServicesForGateway(gw) {
			out = append(out, b.virtualServiceSource(vs))
		}
	}
	if len(out) == 0 {
		return b.defaultSource()
	}
	return out
}

// gatewaySource resolves a namespace/name gateway reference, including its resource version,
// from the configuration store.
func (b *sourceBuilder) gatewaySource(namespaceName string) (model.ResourceSource, bool) {
	ns, name, ok := strings.Cut(namespaceName, "/")
	if !ok {
		return model.ResourceSource{}, false
	}
	var rv string
	if b.server != nil && b.server.Env != nil && b.server.Env.ConfigStore != nil {
		if cfg := b.server.Env.ConfigStore.Get(gvk.Gateway, name, ns); cfg != nil {
			rv = cfg.ResourceVersion
		}
	}
	return model.ResourceSource{
		Kind:      model.SourceGateway,
		Name:      name,
		Namespace: ns,
		Version:   rv,
		Cluster:   b.clusterID(),
	}, true
}

func (b *sourceBuilder) virtualServicesForGateway(namespaceName string) []*config.Config {
	if b.proxy.SidecarScope == nil {
		return nil
	}
	return b.proxy.SidecarScope.GatewayVirtualServices(namespaceName)
}

// gatewayRouteSources attributes RDS resources for a router.
//   - http.<port>            -> gateways owning that port + their VirtualServices
//   - https.<port>.<pn>.<gw>.<ns>[.<bind>] -> the gateway encoded in the route name + its VS
func (b *sourceBuilder) gatewayRouteSources(routeName string) []model.ResourceSource {
	mg := b.proxy.MergedGateway
	if mg == nil {
		return b.defaultSource()
	}
	parts := strings.Split(routeName, ".")
	if len(parts) < 2 {
		return b.defaultSource()
	}
	switch parts[0] {
	case "http":
		port, err := strconv.Atoi(parts[1])
		if err != nil {
			return b.defaultSource()
		}
		return b.gatewaySources(b.gatewayOwnersOnPort(port))
	case "https":
		// https.<port>.<portName>.<gatewayName>.<namespace>[.<bind>]
		if len(parts) < 5 {
			return b.defaultSource()
		}
		gw := parts[3] + "/" + parts[4]
		for _, candidate := range mg.GatewayNames {
			if candidate == gw {
				return b.gatewaySources([]string{gw})
			}
		}
		// Still attribute by name even if the gateway is no longer merged (transient state).
		return b.gatewaySources([]string{gw})
	default:
		return b.defaultSource()
	}
}

func serviceHasPort(svc *model.Service, port int) bool {
	if svc == nil {
		return false
	}
	for _, p := range svc.Ports {
		if p != nil && p.Port == port {
			return true
		}
	}
	return false
}

type setsHostName map[host.Name]struct{}

// ResourceSourceEntry is one row of the /debug/resource_sources output: a generated Envoy
// resource together with the configuration objects that produced it.
type ResourceSourceEntry struct {
	Type    model.ResourceType     `json:"type"`
	Name    string                 `json:"name"`
	Sources []model.ResourceSource `json:"sources"`
}

// ResourceSourcesDebug is the read-only /debug/resource_sources payload for one proxy.
type ResourceSourcesDebug struct {
	ProxyID   string                `json:"proxyID"`
	Cluster   cluster.ID            `json:"cluster,omitempty"`
	Version   uint64                `json:"version"`
	Count     int                   `json:"count"`
	Resources []ResourceSourceEntry `json:"resources"`
}

// resourceSourcesz serves the read-only resource source index. It never computes or pushes
// configuration; it only reads what generation already observed.
//
//	/debug/resource_sources                         -> list proxy IDs with recorded sources
//	/debug/resource_sources?proxyID=<id>            -> all resources of the proxy
//	/debug/resource_sources?proxyID=<id>&type=cluster&name=<n> -> a single resource
func (s *DiscoveryServer) resourceSourcesz(w http.ResponseWriter, req *http.Request) {
	if s.SourceIndex == nil {
		writeJSON(w, ResourceSourcesDebug{}, req)
		return
	}
	proxyID := req.URL.Query().Get("proxyID")
	if proxyID == "" {
		// Default to the proxy resolved from the debug connection query parameters when present.
		if id, con := s.getDebugConnection(req); con != nil {
			proxyID = id
		}
	}
	if proxyID == "" {
		writeJSON(w, map[string]any{"proxies": s.SourceIndex.ProxyIDs(), "version": s.SourceIndex.Version()}, req)
		return
	}

	// Accept the full Envoy node ID as well as the istioctl-friendly "<pod>" or "<pod>.<namespace>"
	// shorthand and resolve it against the proxies this instance has recorded sources for.
	resolvedID := s.resolveSourceProxyID(proxyID, req.URL.Query().Get("namespace"))
	if resolvedID == "" {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("No recorded resource sources for proxy " + proxyID +
			" on this Pilot instance. It may be connected to another instance, or has not yet received configuration.\n"))
		return
	}
	proxyID = resolvedID

	snapshot, version, ok := s.SourceIndex.Snapshot(proxyID)
	if !ok {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("No recorded resource sources for proxy " + proxyID +
			" on this Pilot instance. It may be connected to another instance, or has not yet received configuration.\n"))
		return
	}

	filterType := model.ResourceType(req.URL.Query().Get("type"))
	filterName := req.URL.Query().Get("name")

	out := ResourceSourcesDebug{ProxyID: proxyID, Version: version}
	if con := s.adsClient(proxyID); con != nil && con.proxy.Metadata != nil {
		out.Cluster = con.proxy.Metadata.ClusterID
	}
	for ref, sources := range snapshot {
		if filterType != "" && ref.Type != filterType {
			continue
		}
		if filterName != "" && ref.Name != filterName {
			continue
		}
		cp := make([]model.ResourceSource, len(sources))
		copy(cp, sources)
		out.Resources = append(out.Resources, ResourceSourceEntry{
			Type:    ref.Type,
			Name:    ref.Name,
			Sources: cp,
		})
	}
	sort.Slice(out.Resources, func(i, j int) bool {
		if out.Resources[i].Type != out.Resources[j].Type {
			return out.Resources[i].Type < out.Resources[j].Type
		}
		return out.Resources[i].Name < out.Resources[j].Name
	})
	out.Count = len(out.Resources)
	writeJSON(w, out, req)
}

// adsClient returns the active connection for a proxy ID, if any.
func (s *DiscoveryServer) adsClient(proxyID string) *Connection {
	s.adsClientsMutex.RLock()
	defer s.adsClientsMutex.RUnlock()
	for _, con := range s.adsClients {
		if con.proxy.ID == proxyID {
			return con
		}
	}
	return nil
}

// resolveSourceProxyID maps a full Envoy node ID, "<pod>.<namespace>", or "<pod>" shorthand to
// the recorded full proxy ID. Empty string means no unique proxy matched.
func (s *DiscoveryServer) resolveSourceProxyID(input, namespace string) string {
	ids := s.SourceIndex.ProxyIDs()
	for _, id := range ids {
		if id == input {
			return id
		}
	}
	// Envoy node IDs embed the workload as "<pod>.<namespace>" between '~' separators.
	candidate := input
	if namespace != "" && !strings.Contains(input, ".") {
		candidate = input + "." + namespace
	}
	needle := "~" + candidate + "~"
	var partial []string
	for _, id := range ids {
		if strings.Contains(id, needle) {
			return id
		}
		if namespace == "" && strings.Contains(id, "~"+input+".") {
			partial = append(partial, id)
		}
	}
	if len(partial) == 1 {
		return partial[0]
	}
	return ""
}

// virtualServiceMatchesHosts reports whether cfg routes for any of the service hostnames
// exposed on the resource's port. An explicit destination port always narrows the match to the
// same port.
func virtualServiceMatchesHosts(cfg *config.Config, portHosts setsHostName, port int) bool {
	if len(portHosts) == 0 {
		return false
	}
	vs, ok := cfg.Spec.(*networking.VirtualService)
	if !ok {
		return false
	}
	hostMatch := func(h string) bool {
		hostname := host.Name(h)
		if _, ok := portHosts[hostname]; ok {
			return true
		}
		// Wildcard VirtualService hosts (e.g. *.example.com) match a concrete service host.
		for svcHost := range portHosts {
			if hostname.Matches(svcHost) {
				return true
			}
		}
		return false
	}
	for _, httpRoute := range vs.GetHttp() {
		for _, dst := range httpRoute.GetRoute() {
			if dst == nil || dst.GetDestination() == nil {
				continue
			}
			if dst.GetDestination().GetPort() != nil &&
				int(dst.GetDestination().GetPort().GetNumber()) != port {
				continue
			}
			if hostMatch(dst.GetDestination().GetHost()) {
				return true
			}
		}
	}
	for _, tlsRoute := range vs.GetTls() {
		for _, dst := range tlsRoute.GetRoute() {
			if dst == nil || dst.GetDestination() == nil {
				continue
			}
			if dst.GetDestination().GetPort() != nil && int(dst.GetDestination().GetPort().GetNumber()) != port {
				continue
			}
			if hostMatch(dst.GetDestination().GetHost()) {
				return true
			}
		}
	}
	for _, tcpRoute := range vs.GetTcp() {
		for _, dst := range tcpRoute.GetRoute() {
			if dst == nil || dst.GetDestination() == nil {
				continue
			}
			if dst.GetDestination().GetPort() != nil && int(dst.GetDestination().GetPort().GetNumber()) != port {
				continue
			}
			if hostMatch(dst.GetDestination().GetHost()) {
				return true
			}
		}
	}
	// Fall back to the VirtualService host list, which normally equals the service hostname.
	for _, h := range vs.GetHosts() {
		if hostMatch(h) {
			return true
		}
	}
	return false
}
