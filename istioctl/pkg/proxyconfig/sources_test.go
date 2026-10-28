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

package proxyconfig

import (
	"bytes"
	"strings"
	"testing"
)

func owningIstiodDump() []byte {
	return []byte(`{
  "proxyID": "myapp-pod.default",
  "cluster": "Kubernetes",
  "version": 7,
  "count": 2,
  "resources": [
    {
      "type": "cluster",
      "name": "outbound|9080||reviews.default.svc.cluster.local",
      "sources": [
        {"kind": "Service", "name": "reviews.default.svc.cluster.local", "namespace": "default", "version": "1024", "cluster": "Kubernetes"}
      ]
    },
    {
      "type": "cluster",
      "name": "BlackHoleCluster",
      "sources": [
        {"kind": "default", "name": "default", "cluster": "Kubernetes"}
      ]
    }
  ]
}`)
}

func TestSelectResourceSources(t *testing.T) {
	t.Run("picks owning istiod", func(t *testing.T) {
		res := map[string][]byte{
			"istiod-a": []byte("No recorded resource sources for proxy on this Pilot instance.\n"),
			"istiod-b": owningIstiodDump(),
		}
		d, err := selectResourceSources(res)
		if err != nil {
			t.Fatal(err)
		}
		if d.ProxyID != "myapp-pod.default" || d.Version != 7 || d.Count != 2 {
			t.Fatalf("unexpected dump selected: %+v", d)
		}
	})

	t.Run("none own the proxy", func(t *testing.T) {
		res := map[string][]byte{
			"istiod-a": []byte("not found"),
			"istiod-b": []byte("also not found"),
		}
		if _, err := selectResourceSources(res); err == nil {
			t.Fatal("expected an error when no istiod owns the proxy")
		}
	})

	t.Run("empty", func(t *testing.T) {
		if _, err := selectResourceSources(map[string][]byte{}); err == nil {
			t.Fatal("expected an error for empty responses")
		}
	})
}

func TestPrintResourceSourcesSummary(t *testing.T) {
	d, err := selectResourceSources(map[string][]byte{"istiod": owningIstiodDump()})
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if err := printResourceSourcesSummary(&buf, d); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	for _, want := range []string{
		"Proxy: myapp-pod.default",
		"Cluster: Kubernetes",
		"Index version: 7",
		"Service/reviews.default.svc.cluster.local",
		"default/default",
		"1024",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("summary output missing %q\n%s", want, out)
		}
	}
}

func TestPrintResourceSourcesJSONAndYAML(t *testing.T) {
	d, err := selectResourceSources(map[string][]byte{"istiod": owningIstiodDump()})
	if err != nil {
		t.Fatal(err)
	}
	var j bytes.Buffer
	if err := printResourceSourcesJSON(&j, d); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(j.String(), `"kind": "Service"`) || !strings.Contains(j.String(), `"version": "1024"`) {
		t.Fatalf("json output missing source details: %s", j.String())
	}
	var y bytes.Buffer
	if err := printResourceSourcesYAML(&y, d); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(y.String(), "kind: Service") || !strings.Contains(y.String(), "version: \"1024\"") {
		t.Fatalf("yaml output missing source details: %s", y.String())
	}
}
