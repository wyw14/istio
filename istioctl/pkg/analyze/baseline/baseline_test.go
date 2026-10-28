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

package baseline

import (
	"strings"
	"testing"
	"time"

	"istio.io/istio/pkg/cluster"
	"istio.io/istio/pkg/config"
	"istio.io/istio/pkg/config/analysis/diag"
	"istio.io/istio/pkg/config/analysis/legacy/source/kube"
	"istio.io/istio/pkg/config/resource"
)

func mkMsg(level diag.Level, code, kind, ns, name, clusterID string, line int, params ...any) diag.Message {
	return diag.Message{
		Type: diag.NewMessageType(level, code, "template %v"),
		Resource: &resource.Instance{
			Origin: &kube.Origin{
				Type:     config.GroupVersionKind{Kind: kind},
				FullName: resource.FullName{Namespace: resource.Namespace(ns), Name: resource.LocalName(name)},
				Cluster:  cluster.ID(clusterID),
			},
		},
		Line:       line,
		Parameters: params,
	}
}

func mkMsgNoResource(level diag.Level, code string) diag.Message {
	return diag.Message{
		Type:       diag.NewMessageType(level, code, "template %v"),
		Resource:   nil,
		Parameters: []any{"x"},
	}
}

func mustParse(t *testing.T, doc string) *Baseline {
	t.Helper()
	b, err := Parse([]byte(doc))
	if err != nil {
		t.Fatalf("unexpected parse error: %v", err)
	}
	return b
}

func TestClassifyKnownAndNew(t *testing.T) {
	msgs := diag.Messages{
		mkMsg(diag.Warning, "IST0103", "Pod", "testing", "mypod", "", 12, "mypod"),
		mkMsg(diag.Warning, "IST0103", "Pod", "testing", "otherpod", "", 99, "otherpod"),
	}
	b, _ := FromMessages(msgs, time.Now())
	if len(b.Entries) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(b.Entries))
	}

	// Re-run: identical diagnostics but with different line numbers and reversed order.
	current := diag.Messages{
		mkMsg(diag.Warning, "IST0103", "Pod", "testing", "otherpod", "", 7, "otherpod"),
		mkMsg(diag.Warning, "IST0103", "Pod", "testing", "mypod", "", 1500, "mypod"),
	}
	r := Classify(b, current, time.Now())
	if len(r.New) != 0 {
		t.Fatalf("expected no new messages, got %d: %v", len(r.New), r.New)
	}
	if len(r.Known) != 2 {
		t.Fatalf("expected 2 known messages, got %d", len(r.Known))
	}
	if len(r.Disappeared) != 0 || len(r.Expired) != 0 {
		t.Fatalf("expected no disappeared/expired entries, got %d/%d", len(r.Disappeared), len(r.Expired))
	}
}

func TestClassifyNewDisappearedAndParams(t *testing.T) {
	exported := diag.Messages{
		mkMsg(diag.Warning, "IST0103", "Pod", "testing", "oldpod", "", 1, "oldpod"),
	}
	b, _ := FromMessages(exported, time.Now())

	current := diag.Messages{
		// Same resource and code but a changed message parameter -> new.
		mkMsg(diag.Warning, "IST0103", "Pod", "testing", "oldpod", "", 1, "different-parameter"),
		// A genuinely new diagnostic.
		mkMsg(diag.Error, "IST0102", "Pod", "testing", "newpod", "", 2, "newpod"),
	}
	r := Classify(b, current, time.Now())
	if len(r.New) != 2 {
		t.Fatalf("expected 2 new messages, got %d", len(r.New))
	}
	if len(r.Known) != 0 {
		t.Fatalf("expected no known messages, got %d", len(r.Known))
	}
	if len(r.Disappeared) != 1 || r.Disappeared[0].Code != "IST0103" {
		t.Fatalf("expected the old entry to be reported as disappeared, got %+v", r.Disappeared)
	}
}

func TestSeverityEscalationCannotBeMasked(t *testing.T) {
	exported := diag.Messages{
		mkMsg(diag.Warning, "IST0103", "Pod", "testing", "mypod", "", 1, "mypod"),
	}
	b, _ := FromMessages(exported, time.Now())

	// Warning -> Error: must be treated as a new diagnostic.
	escalated := diag.Messages{
		mkMsg(diag.Error, "IST0103", "Pod", "testing", "mypod", "", 1, "mypod"),
	}
	r := Classify(b, escalated, time.Now())
	if len(r.New) != 1 || r.New[0].Type.Level() != diag.Error {
		t.Fatalf("expected escalated Error to be new, got %+v", r.New)
	}
	if len(r.Known) != 0 {
		t.Fatalf("escalated diagnostic must not be known, got %d known", len(r.Known))
	}
	if len(r.Disappeared) != 1 || r.Disappeared[0].Level != "Warning" {
		t.Fatalf("expected the Warning baseline entry to be reported as disappeared, got %+v", r.Disappeared)
	}

	// Error -> Warning (de-escalation) is also a changed diagnostic.
	r = Classify(b, diag.Messages{
		mkMsg(diag.Info, "IST0103", "Pod", "testing", "mypod", "", 1, "mypod"),
	}, time.Now())
	if len(r.New) != 1 || len(r.Known) != 0 {
		t.Fatalf("expected de-escalated diagnostic to be new, got %+v", r.New)
	}
}

func TestClusterIsPartOfIdentity(t *testing.T) {
	exported := diag.Messages{
		mkMsg(diag.Warning, "IST0103", "Pod", "testing", "mypod", "cluster-west", 1, "mypod"),
	}
	b, _ := FromMessages(exported, time.Now())

	// Same diagnostic reported from a different cluster must not match.
	r := Classify(b, diag.Messages{
		mkMsg(diag.Warning, "IST0103", "Pod", "testing", "mypod", "cluster-east", 1, "mypod"),
	}, time.Now())
	if len(r.New) != 1 || len(r.Disappeared) != 1 {
		t.Fatalf("expected cluster mismatch to produce a new diagnostic + disappeared entry, got new=%d disappeared=%d",
			len(r.New), len(r.Disappeared))
	}

	// Empty cluster (file-only / local analysis) must not match a remote entry.
	r = Classify(b, diag.Messages{
		mkMsg(diag.Warning, "IST0103", "Pod", "testing", "mypod", "", 1, "mypod"),
	}, time.Now())
	if len(r.New) != 1 {
		t.Fatalf("expected empty cluster not to match the remote baseline entry")
	}
}

func TestExpiry(t *testing.T) {
	future := time.Now().Add(time.Hour).UTC()
	past := time.Now().Add(-time.Hour).UTC()
	b := &Baseline{
		Version: Version,
		Entries: []Entry{
			{
				Code:       "IST0103",
				Level:      "Warning",
				Resource:   "Pod testing/mypod",
				Parameters: []any{"mypod"},
				ExpiresAt:  &future,
			},
			{
				Code:       "IST0102",
				Level:      "Error",
				Resource:   "Pod testing/otherpod",
				Parameters: []any{"otherpod"},
				ExpiresAt:  &past,
			},
		},
	}

	r := Classify(b, diag.Messages{
		mkMsg(diag.Warning, "IST0103", "Pod", "testing", "mypod", "", 1, "mypod"),
		mkMsg(diag.Error, "IST0102", "Pod", "testing", "otherpod", "", 1, "otherpod"),
	}, time.Now())
	if len(r.Known) != 1 || r.Known[0].Type.Code() != "IST0103" {
		t.Fatalf("expected only the unexpired entry to match, got known=%+v", r.Known)
	}
	if len(r.New) != 1 || r.New[0].Type.Code() != "IST0102" {
		t.Fatalf("expected the expired diagnostic to resurface as new, got new=%+v", r.New)
	}
	if len(r.Expired) != 1 || r.Expired[0].Code != "IST0102" {
		t.Fatalf("expected IST0102 to be reported as expired, got %+v", r.Expired)
	}
	if len(r.Disappeared) != 0 {
		t.Fatalf("expected no disappeared entries, got %+v", r.Disappeared)
	}
}

func TestExpiryBoundaryIsInclusive(t *testing.T) {
	at := time.Date(2026, 10, 28, 12, 0, 0, 0, time.UTC)
	b := &Baseline{
		Version: Version,
		Entries: []Entry{{
			Code:       "IST0103",
			Level:      "Warning",
			Resource:   "Pod testing/mypod",
			Parameters: []any{"mypod"},
			ExpiresAt:  &at,
		}},
	}
	// At the exact expiry instant the entry must no longer accept diagnostics.
	r := Classify(b, diag.Messages{
		mkMsg(diag.Warning, "IST0103", "Pod", "testing", "mypod", "", 1, "mypod"),
	}, at)
	if len(r.New) != 1 || len(r.Expired) != 1 {
		t.Fatalf("expected entry to be expired at the expiry instant, got %+v", r)
	}
}

func TestMessageWithoutResourceIdentityCanNeverBeHidden(t *testing.T) {
	b := mustParse(t, `version: v1alpha1
entries:
- code: IST9999
  level: Warning
  resource: Something some-resource
`)
	r := Classify(b, diag.Messages{mkMsgNoResource(diag.Warning, "IST9999")}, time.Now())
	if len(r.New) != 1 || len(r.Known) != 0 {
		t.Fatalf("a diagnostic without resource identity must never be accepted by a baseline")
	}

	// Export must skip such diagnostics.
	out, skipped := FromMessages(diag.Messages{
		mkMsgNoResource(diag.Warning, "IST9999"),
		mkMsg(diag.Warning, "IST0103", "Pod", "testing", "mypod", "", 1, "mypod"),
	}, time.Now())
	if skipped != 1 {
		t.Fatalf("expected exactly 1 skipped diagnostic, got %d", skipped)
	}
	if len(out.Entries) != 1 || out.Entries[0].Code != "IST0103" {
		t.Fatalf("expected only the identifiable diagnostic to be exported, got %+v", out.Entries)
	}
}

func TestExportRoundTrip(t *testing.T) {
	now := time.Date(2026, 10, 28, 12, 0, 0, 0, time.UTC)
	msgs := diag.Messages{
		mkMsg(diag.Error, "IST0102", "Pod", "testing", "a", "", 5, "a"),
		mkMsg(diag.Warning, "IST0103", "Pod", "testing", "b", "west", 9, "b"),
	}
	b, _ := FromMessages(msgs, now)
	data, err := Marshal(b)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := Parse(data)
	if err != nil {
		t.Fatalf("exported baseline failed to parse: %v\n%s", err, string(data))
	}
	if parsed.Version != Version || !parsed.Created.Equal(now) {
		t.Fatalf("unexpected parsed header: %+v", parsed)
	}
	r := Classify(parsed, msgs, now)
	if len(r.Known) != 2 || len(r.New) != 0 {
		t.Fatalf("expected all messages to match after round trip, got %+v", r)
	}
}

func TestParseRejectsMalformedDocuments(t *testing.T) {
	cases := map[string]string{
		"empty":            "",
		"invalid yaml":     "entries: [\n",
		"unknown version":  "version: v9\nentries: []\n",
		"no entries":       "version: v1alpha1\nentries: []\n",
		"missing code":     "version: v1alpha1\nentries:\n- level: Warning\n  resource: Pod a/b\n",
		"missing resource": "version: v1alpha1\nentries:\n- code: IST0103\n  level: Warning\n",
		"invalid level":    "version: v1alpha1\nentries:\n- code: IST0103\n  level: Catastrophe\n  resource: Pod a/b\n",
		"unknown field":    "version: v1alpha1\nbogus: true\nentries: []\n",
		"invalid expiry":   "version: v1alpha1\nentries:\n- code: IST0103\n  level: Warning\n  resource: Pod a/b\n  expiresAt: tomorrow\n",
		"duplicate entry":  "version: v1alpha1\nentries:\n- {code: IST0103, level: Warning, resource: Pod a/b}\n- {code: IST0103, level: Warning, resource: Pod a/b}\n",
		"null entry":       "version: v1alpha1\nentries:\n- null\n",
	}
	for name, doc := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := Parse([]byte(doc)); err == nil {
				t.Fatalf("expected %q to be rejected", name)
			}
		})
	}
}

func TestParseAcceptsDifferentParameterEncodings(t *testing.T) {
	// Numeric parameters written as YAML integers must still match int64 params.
	b := mustParse(t, `version: v1alpha1
entries:
- code: IST0128
  level: Warning
  resource: Pod testing/mypod
  parameters:
  - "mypod"
  - 7
`)
	r := Classify(b, diag.Messages{
		mkMsg(diag.Warning, "IST0128", "Pod", "testing", "mypod", "", 3, "mypod", int64(7)),
	}, time.Now())
	if len(r.Known) != 1 {
		t.Fatalf("expected parameter encoding differences to match, got %+v", r)
	}
}

func TestEntryStringIsStable(t *testing.T) {
	expires := time.Date(2026, 12, 31, 23, 59, 59, 0, time.UTC)
	s := Entry{
		Code:       "IST0103",
		Level:      "Warning",
		Resource:   "Pod testing/mypod",
		Cluster:    "west",
		Parameters: []any{"mypod"},
		ExpiresAt:  &expires,
	}.String()
	for _, want := range []string{"Warning", "[IST0103]", "cluster-west", "Pod testing/mypod", "2026-12-31"} {
		if !strings.Contains(s, want) {
			t.Fatalf("entry string %q missing %q", s, want)
		}
	}
}
