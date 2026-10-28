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
	"testing"

	"istio.io/istio/pkg/cluster"
)

func svcSrc(version string) ResourceSource {
	return ResourceSource{Kind: SourceService, Name: "reviews.default.svc.cluster.local", Namespace: "default", Version: version}
}

func vsSrc(version string) ResourceSource {
	return ResourceSource{Kind: SourceVirtualService, Name: "reviews-vs", Namespace: "default", Version: version}
}

func defaultSrc() ResourceSource {
	return ResourceSource{Kind: SourceDefault, Name: "default"}
}

func TestResourceSourceIndexPerTypeReplacement(t *testing.T) {
	idx := NewResourceSourceIndex()
	const proxy = "sidecar~1.1.1.1~p.default~default.svc.cluster.local"

	v1 := idx.Record(proxy, ClusterResource, ResourceEntries{
		"outbound|9080||reviews": {svcSrc("100")},
		"BlackHoleCluster":       {defaultSrc()},
	})
	if v1 != 1 {
		t.Fatalf("expected version 1, got %d", v1)
	}
	// A separate type push must not clobber cluster data.
	v2 := idx.Record(proxy, ListenerResource, ResourceEntries{
		"0.0.0.0_9080": {svcSrc("100")},
	})
	if v2 != 2 {
		t.Fatalf("expected version 2, got %d", v2)
	}

	snap, pver, ok := idx.Snapshot(proxy)
	if !ok {
		t.Fatal("snapshot missing")
	}
	if pver != v2 {
		t.Fatalf("proxy version %d, want %d", pver, v2)
	}
	if len(snap) != 3 {
		t.Fatalf("expected 3 merged resources across types, got %d: %+v", len(snap), snap)
	}
	if got, ok := idx.Lookup(proxy, ResourceRef{Type: ClusterResource, Name: "BlackHoleCluster"}); !ok || got[0].Kind != SourceDefault {
		t.Fatalf("default cluster lookup wrong: %v %v", got, ok)
	}
}

func TestResourceSourceIndexDeletionLeavesNoStaleEntries(t *testing.T) {
	idx := NewResourceSourceIndex()
	const proxy = "proxy"

	idx.Record(proxy, ClusterResource, ResourceEntries{
		"outbound|9080||reviews": {svcSrc("100")},
		"outbound|80||ratings":   {svcSrc("101")},
	})
	// Simulate regeneration after the ratings Service is deleted: a fresh per-type map that no
	// longer contains it. Whole-map replacement must not leave the old source behind.
	idx.Record(proxy, ClusterResource, ResourceEntries{
		"outbound|9080||reviews": {svcSrc("102")},
	})

	snap, _, ok := idx.Snapshot(proxy)
	if !ok {
		t.Fatal("snapshot missing")
	}
	if _, present := snap[ResourceRef{Type: ClusterResource, Name: "outbound|80||ratings"}]; present {
		t.Fatal("deleted service source must not remain in index")
	}
	sources, ok := idx.Lookup(proxy, ResourceRef{Type: ClusterResource, Name: "outbound|9080||reviews"})
	if !ok || sources[0].Version != "102" {
		t.Fatalf("expected surviving service at version 102, got %+v", sources)
	}
}

func TestResourceSourceIndexRecordDelta(t *testing.T) {
	idx := NewResourceSourceIndex()
	const proxy = "proxy"

	idx.Record(proxy, ClusterResource, ResourceEntries{
		"outbound|9080||reviews": {svcSrc("100")},
		"outbound|80||ratings":   {svcSrc("101")},
	})
	// Incremental push: reviews updated to a new resource version, ratings removed.
	ver := idx.RecordDelta(proxy, ClusterResource,
		ResourceEntries{"outbound|9080||reviews": {svcSrc("200")}},
		[]string{"outbound|80||ratings"})

	snap, pver, _ := idx.Snapshot(proxy)
	if pver != ver {
		t.Fatalf("proxy version %d != returned %d", pver, ver)
	}
	if _, present := snap[ResourceRef{Type: ClusterResource, Name: "outbound|80||ratings"}]; present {
		t.Fatal("delta-removed cluster source must not remain")
	}
	sources := snap[ResourceRef{Type: ClusterResource, Name: "outbound|9080||reviews"}]
	if len(sources) != 1 || sources[0].Version != "200" {
		t.Fatalf("delta-updated source wrong: %+v", sources)
	}
}

func TestResourceSourceIndexIncrementalVersionMonotonic(t *testing.T) {
	idx := NewResourceSourceIndex()
	last := uint64(0)
	for i := 0; i < 5; i++ {
		v := idx.Record("p", RouteResource, ResourceEntries{"80": {vsSrc("1")}})
		if v <= last {
			t.Fatalf("version must be monotonic: %d after %d", v, last)
		}
		last = v
	}
	if idx.Version() != 5 {
		t.Fatalf("global version %d, want 5", idx.Version())
	}
}

func TestResourceSourceIndexRemoveProxy(t *testing.T) {
	idx := NewResourceSourceIndex()
	idx.Record("a", ClusterResource, ResourceEntries{"c": {defaultSrc()}})
	idx.Record("b", ClusterResource, ResourceEntries{"c": {defaultSrc()}})
	idx.RemoveProxy("a")
	if ids := idx.ProxyIDs(); len(ids) != 1 || ids[0] != "b" {
		t.Fatalf("expected only proxy b to remain, got %v", ids)
	}
	if _, _, ok := idx.Snapshot("a"); ok {
		t.Fatal("removed proxy snapshot must be gone")
	}
}

func TestResourceSourceIndexLookupIsCopy(t *testing.T) {
	idx := NewResourceSourceIndex()
	idx.Record("p", ClusterResource, ResourceEntries{"c": {svcSrc("1")}})
	got, ok := idx.Lookup("p", ResourceRef{Type: ClusterResource, Name: "c"})
	if !ok {
		t.Fatal("missing")
	}
	got[0].Version = "mutated"
	again, _ := idx.Lookup("p", ResourceRef{Type: ClusterResource, Name: "c"})
	if again[0].Version != "1" {
		t.Fatalf("Lookup must return a defensive copy, stored version changed to %q", again[0].Version)
	}
}

func TestSortSourcesDeduplicatesAndOrders(t *testing.T) {
	clusterC := cluster.ID("cluster-1")
	in := []ResourceSource{
		{Kind: SourceVirtualService, Name: "b", Namespace: "ns", Version: "2"},
		{Kind: SourceService, Name: "a", Namespace: "ns", Version: "1", Cluster: clusterC},
		{Kind: SourceVirtualService, Name: "b", Namespace: "ns", Version: "2"},
		{Kind: SourceDefault, Name: "default"},
	}
	out := SortSources(in)
	if len(out) != 3 {
		t.Fatalf("expected 3 deduped sources, got %d: %+v", len(out), out)
	}
	// Lexicographic Kind ordering: "Service" < "VirtualService" < "default".
	if out[0].Kind != SourceService || out[1].Kind != SourceVirtualService || out[2].Kind != SourceDefault {
		t.Fatalf("unexpected order: %+v", out)
	}
	if out[0].Cluster != clusterC {
		t.Fatal("cluster id not preserved")
	}
}
