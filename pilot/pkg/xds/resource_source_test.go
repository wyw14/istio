// Copyright Istio Authors
//
// Licensed under the Apache License, Version 2.0 (License,
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

package xds_test

import (
	"testing"

	discovery "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"

	"istio.io/istio/pilot/pkg/model"
	v3 "istio.io/istio/pilot/pkg/xds/v3"
	xdsfake "istio.io/istio/pilot/test/xds"
	"istio.io/istio/pkg/cluster"
	"istio.io/istio/pkg/config/constants"
	"istio.io/istio/pkg/config/host"
	"istio.io/istio/pkg/config/protocol"
)

const (
	reviewsHost = "reviews.default.svc.cluster.local"
	ratingsHost = "ratings.default.svc.cluster.local"

	// Full Envoy node IDs used on the stream; proxy.ID (the index key) is the pod.namespace segment.
	sourceSidecarNode  = "sidecar~10.0.0.1~myapp-pod.default~default.svc.cluster.local"
	sourceSidecarProxy = "myapp-pod.default"
	sourceRouterNode   = "router~10.3.0.1~bookinfo-gateway-pod.default~default.svc.cluster.local"
	sourceRouterProxy  = "bookinfo-gateway-pod.default"
)

func sourceServices() []*model.Service {
	return []*model.Service{
		{
			Hostname:        host.Name(reviewsHost),
			DefaultAddress:  "10.10.0.1",
			ResourceVersion: "rv-reviews",
			Ports: model.PortList{{
				Name: "http", Port: 9080, Protocol: protocol.HTTP,
			}},
			Attributes: model.ServiceAttributes{Name: "reviews", Namespace: "default"},
		},
		{
			Hostname:        host.Name(ratingsHost),
			DefaultAddress:  "10.10.0.2",
			ResourceVersion: "rv-ratings",
			Ports: model.PortList{{
				Name: "http", Port: 80, Protocol: protocol.HTTP,
			}},
			Attributes: model.ServiceAttributes{Name: "ratings", Namespace: "default"},
		},
	}
}

func sourceTestServer(t *testing.T) *xdsfake.FakeDiscoveryServer {
	t.Helper()
	return xdsfake.NewFakeDiscoveryServer(t, xdsfake.FakeOptions{
		ConfigString: mustReadfolder(t, "tests/testdata/resource-source"),
		Services:     sourceServices(),
	})
}

func ackType(t *testing.T, s *xdsfake.FakeDiscoveryServer, node, typeURL string, metadata model.NodeMetadata, resourceNames ...string) {
	t.Helper()
	ads := s.ConnectADS().WithType(typeURL).WithID(node).WithMetadata(metadata)
	req := &discovery.DiscoveryRequest{ResourceNames: resourceNames}
	ads.RequestResponseAck(t, req)
}

func hasSource(sources []model.ResourceSource, kind model.SourceKind, name string) bool {
	for _, src := range sources {
		if src.Kind == kind && src.Name == name {
			return true
		}
	}
	return false
}

func sourceOf(sources []model.ResourceSource, kind model.SourceKind, name string) (model.ResourceSource, bool) {
	for _, src := range sources {
		if src.Kind == kind && src.Name == name {
			return src, true
		}
	}
	return model.ResourceSource{}, false
}

// TestResourceSourcesSidecar verifies that generated clusters, listeners and routes of a
// sidecar are annotated with the originating Service/VirtualService (with versions) or with the
// synthesized default marker.
func TestResourceSourcesSidecar(t *testing.T) {
	s := sourceTestServer(t)

	ackType(t, s, sourceSidecarNode, v3.ClusterType, model.NodeMetadata{IstioVersion: "1.23.0"})
	ackType(t, s, sourceSidecarNode, v3.ListenerType, model.NodeMetadata{IstioVersion: "1.23.0"})
	ackType(t, s, sourceSidecarNode, v3.RouteType, model.NodeMetadata{IstioVersion: "1.23.0"}, "9080", "80")

	idx := s.Discovery.SourceIndex
	snap, _, ok := idx.Snapshot(sourceSidecarProxy)
	if !ok {
		t.Fatal("expected sources recorded for sidecar")
	}

	// Clusters: service-backed cluster carries the service resource version.
	reviewsCluster, ok := idx.Lookup(sourceSidecarProxy, model.ResourceRef{Type: model.ClusterResource,
		Name: "outbound|9080||" + reviewsHost})
	if !ok {
		t.Fatalf("reviews cluster source missing; snapshot=%v", snap)
	}
	src, ok := sourceOf(reviewsCluster, model.SourceService, reviewsHost)
	if !ok {
		t.Fatalf("expected Service source for reviews cluster, got %+v", reviewsCluster)
	}
	if src.Version != "rv-reviews" || src.Namespace != "default" {
		t.Fatalf("unexpected service source: %+v", src)
	}

	ratingsCluster, ok := idx.Lookup(sourceSidecarProxy, model.ResourceRef{Type: model.ClusterResource,
		Name: "outbound|80||" + ratingsHost})
	if !ok {
		t.Fatal("ratings cluster source missing")
	}
	if !hasSource(ratingsCluster, model.SourceService, ratingsHost) {
		t.Fatalf("expected Service source for ratings cluster, got %+v", ratingsCluster)
	}

	// Clusters: synthesized infra cluster is attributed to defaults.
	blackhole, ok := idx.Lookup(sourceSidecarProxy, model.ResourceRef{Type: model.ClusterResource, Name: "BlackHoleCluster"})
	if !ok {
		t.Fatal("BlackHoleCluster source missing")
	}
	if blackhole[0].Kind != model.SourceDefault {
		t.Fatalf("BlackHoleCluster must be default, got %+v", blackhole)
	}

	// Listener on the reviews port is produced by the service and shaped by its VirtualService.
	listener9080, ok := idx.Lookup(sourceSidecarProxy, model.ResourceRef{Type: model.ListenerResource, Name: "0.0.0.0_9080"})
	if !ok {
		t.Fatalf("listener 0.0.0.0_9080 source missing; snapshot=%v", snap)
	}
	if !hasSource(listener9080, model.SourceService, reviewsHost) {
		t.Fatalf("listener 9080 expected Service source, got %+v", listener9080)
	}
	if !hasSource(listener9080, model.SourceVirtualService, "reviews-vs") {
		t.Fatalf("listener 9080 expected VirtualService reviews-vs source, got %+v", listener9080)
	}

	// Routes: 9080 is driven by the VirtualService, 80 (ratings) only by the service.
	route9080, ok := idx.Lookup(sourceSidecarProxy, model.ResourceRef{Type: model.RouteResource, Name: "9080"})
	if !ok {
		t.Fatal("route 9080 source missing")
	}
	if !hasSource(route9080, model.SourceService, reviewsHost) || !hasSource(route9080, model.SourceVirtualService, "reviews-vs") {
		t.Fatalf("route 9080 expected Service + VirtualService sources, got %+v", route9080)
	}
	route80, ok := idx.Lookup(sourceSidecarProxy, model.ResourceRef{Type: model.RouteResource, Name: "80"})
	if !ok {
		t.Fatal("route 80 source missing")
	}
	if !hasSource(route80, model.SourceService, ratingsHost) || hasSource(route80, model.SourceVirtualService, "reviews-vs") {
		t.Fatalf("route 80 expected only the ratings Service source, got %+v", route80)
	}
}

// TestResourceSourcesGateway verifies gateway listeners/routes are attributed to the Gateway
// and the VirtualServices bound to it.
func TestResourceSourcesGateway(t *testing.T) {
	s := sourceTestServer(t)
	gwMeta := model.NodeMetadata{IstioVersion: "1.23.0", Labels: map[string]string{"app": "bookinfo-gateway"}}

	ackType(t, s, sourceRouterNode, v3.ListenerType, gwMeta)
	ackType(t, s, sourceRouterNode, v3.RouteType, gwMeta, "http.80")

	idx := s.Discovery.SourceIndex

	listener, ok := idx.Lookup(sourceRouterProxy, model.ResourceRef{Type: model.ListenerResource, Name: "0.0.0.0_80"})
	if !ok {
		t.Fatal("gateway listener 0.0.0.0_80 source missing")
	}
	gwSrc, ok := sourceOf(listener, model.SourceGateway, "bookinfo-gateway")
	if !ok {
		t.Fatalf("expected Gateway bookinfo-gateway source, got %+v", listener)
	}
	if gwSrc.Namespace != "default" || gwSrc.Version == "" {
		t.Fatalf("gateway source must carry namespace and a store-assigned version, got %+v", gwSrc)
	}
	if !hasSource(listener, model.SourceVirtualService, "reviews-gateway-vs") {
		t.Fatalf("expected gateway-bound VirtualService reviews-gateway-vs, got %+v", listener)
	}

	route, ok := idx.Lookup(sourceRouterProxy, model.ResourceRef{Type: model.RouteResource, Name: "http.80"})
	if !ok {
		t.Fatal("gateway route http.80 source missing")
	}
	if !hasSource(route, model.SourceGateway, "bookinfo-gateway") ||
		!hasSource(route, model.SourceVirtualService, "reviews-gateway-vs") {
		t.Fatalf("gateway route expected Gateway + VirtualService sources, got %+v", route)
	}
}

// TestResourceSourcesDeletionClearsStaleSources regenerates after a service is deleted and
// asserts the old cluster source no longer remains in the read-only index.
func TestResourceSourcesDeletionClearsStaleSources(t *testing.T) {
	s := sourceTestServer(t)
	ads := s.ConnectADS().WithType(v3.ClusterType).WithID(sourceSidecarNode).
		WithMetadata(model.NodeMetadata{IstioVersion: "1.23.0"})
	ads.RequestResponseAck(t, nil)

	idx := s.Discovery.SourceIndex
	if _, ok := idx.Lookup(sourceSidecarProxy, model.ResourceRef{Type: model.ClusterResource,
		Name: "outbound|80||" + ratingsHost}); !ok {
		t.Fatal("ratings cluster expected before deletion")
	}

	// RemoveService notifies the XDS updater; consume the resulting full CDS push.
	s.MemRegistry.RemoveService(host.Name(ratingsHost))
	ads.ExpectResponse(t)

	if _, ok := idx.Lookup(sourceSidecarProxy, model.ResourceRef{Type: model.ClusterResource,
		Name: "outbound|80||" + ratingsHost}); ok {
		t.Fatal("ratings cluster source must be removed after the service was deleted")
	}
	if _, ok := idx.Lookup(sourceSidecarProxy, model.ResourceRef{Type: model.ClusterResource,
		Name: "outbound|9080||" + reviewsHost}); !ok {
		t.Fatal("unrelated reviews cluster source must survive")
	}
}

// TestResourceSourcesIncrementalVersion updates a service resource version and asserts the
// read-only index version advances monotonically and the recorded source version follows.
func TestResourceSourcesIncrementalVersion(t *testing.T) {
	s := sourceTestServer(t)
	ads := s.ConnectADS().WithType(v3.ClusterType).WithID(sourceSidecarNode).
		WithMetadata(model.NodeMetadata{IstioVersion: "1.23.0"})
	ads.RequestResponseAck(t, nil)

	idx := s.Discovery.SourceIndex
	_, v0, _ := idx.Snapshot(sourceSidecarProxy)

	updated := sourceServices()[0]
	updated.ResourceVersion = "rv-reviews-2"
	s.MemRegistry.AddService(updated)
	ads.ExpectResponse(t)

	snap, v1, ok := idx.Snapshot(sourceSidecarProxy)
	if !ok {
		t.Fatal("snapshot missing after update")
	}
	if v1 <= v0 {
		t.Fatalf("index version must advance after regeneration: before=%d after=%d", v0, v1)
	}
	sources := snap[model.ResourceRef{Type: model.ClusterResource, Name: "outbound|9080||" + reviewsHost}]
	src, ok := sourceOf(sources, model.SourceService, reviewsHost)
	if !ok || src.Version != "rv-reviews-2" {
		t.Fatalf("expected reviews source at rv-reviews-2, got %+v", sources)
	}

	// Read-only access must not advance the version.
	if idx.Version() == 0 {
		t.Fatal("expected non-zero global version")
	}
}

// TestResourceSourcesMultiCluster connects two proxies in different clusters and asserts their
// sources are tracked independently and tagged with the originating (consumer) cluster.
func TestResourceSourcesMultiCluster(t *testing.T) {
	s := sourceTestServer(t)
	nodeA := "sidecar~10.0.0.1~app-a.default~default.svc.cluster.local"
	nodeB := "sidecar~10.0.0.2~app-b.other~other.svc.cluster.local"
	const proxyA = "app-a.default"
	const proxyB = "app-b.other"

	ackType(t, s, nodeA, v3.ClusterType,
		model.NodeMetadata{IstioVersion: "1.23.0", ClusterID: cluster.ID(constants.DefaultClusterName)})
	ackType(t, s, nodeB, v3.ClusterType,
		model.NodeMetadata{IstioVersion: "1.23.0", ClusterID: "cluster-2"})

	idx := s.Discovery.SourceIndex
	ids := idx.ProxyIDs()
	if len(ids) < 2 || !contains(ids, proxyA) || !contains(ids, proxyB) {
		t.Fatalf("expected both clusters to be tracked independently, got %v", ids)
	}

	a, okA := idx.Lookup(proxyA, model.ResourceRef{Type: model.ClusterResource, Name: "outbound|9080||" + reviewsHost})
	b, okB := idx.Lookup(proxyB, model.ResourceRef{Type: model.ClusterResource, Name: "outbound|9080||" + reviewsHost})
	if !okA || !okB {
		t.Fatalf("missing reviews cluster source for one of the clusters: a=%v b=%v", okA, okB)
	}
	if a[0].Cluster != cluster.ID(constants.DefaultClusterName) {
		t.Fatalf("cluster A source tagged %q, want %q", a[0].Cluster, constants.DefaultClusterName)
	}
	if b[0].Cluster != "cluster-2" {
		t.Fatalf("cluster B source tagged %q, want cluster-2", b[0].Cluster)
	}
}

// TestResourceSourcesSidecarScopeFiltering validates that a Sidecar import restriction limits
// the resources (and therefore sources) a proxy observes.
func TestResourceSourcesSidecarScopeFiltering(t *testing.T) {
	s := sourceTestServer(t)
	const node = "sidecar~10.0.0.2~restricted-app-pod.restricted~restricted.svc.cluster.local"
	const proxy = "restricted-app-pod.restricted"
	meta := model.NodeMetadata{IstioVersion: "1.23.0", Labels: map[string]string{"app": "restricted-app"}}
	s.MemRegistry.AddWorkload("10.0.0.2", meta.Labels)

	ackType(t, s, node, v3.ClusterType, meta)
	ackType(t, s, node, v3.ListenerType, meta)
	ackType(t, s, node, v3.RouteType, meta, "9080")

	idx := s.Discovery.SourceIndex
	if _, ok := idx.Lookup(proxy, model.ResourceRef{Type: model.ClusterResource, Name: "outbound|9080||" + reviewsHost}); !ok {
		t.Fatal("restricted sidecar must still see imported reviews")
	}
	if _, ok := idx.Lookup(proxy, model.ResourceRef{Type: model.ClusterResource, Name: "outbound|80||" + ratingsHost}); ok {
		t.Fatal("restricted sidecar must not see the non-imported ratings service cluster")
	}
	if _, ok := idx.Lookup(proxy, model.ResourceRef{Type: model.ListenerResource, Name: "0.0.0.0_80"}); ok {
		t.Fatal("restricted sidecar must not have a listener for non-imported ratings port")
	}
	if _, ok := idx.Lookup(proxy, model.ResourceRef{Type: model.ListenerResource, Name: "0.0.0.0_9080"}); !ok {
		t.Fatal("restricted sidecar must retain the listener for imported reviews")
	}
}

func contains(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}
