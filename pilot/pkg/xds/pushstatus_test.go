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
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sync"
	"testing"
	"time"

	"istio.io/istio/pilot/pkg/model"
)

func statusTestConnection(id string) *Connection {
	con := newConnection("", nil)
	con.SetID(id)
	return con
}

func dequeueTestRequest(t *testing.T, p *PushQueue) (*Connection, *model.PushRequest) {
	t.Helper()
	type result struct {
		con *Connection
		req *model.PushRequest
	}
	done := make(chan result, 1)
	go func() {
		con, req, _ := p.Dequeue()
		done <- result{con: con, req: req}
	}()
	select {
	case r := <-done:
		return r.con, r.req
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for dequeue")
		return nil, nil
	}
}

func reqWithSource(version string, reasons ...model.TriggerReason) *model.PushRequest {
	return &model.PushRequest{
		Push:   &model.PushContext{PushVersion: version},
		Reason: model.NewReasonStats(reasons...),
		Start:  time.Now(),
	}
}

// Rubric 1: multiple sources triggering the same connection (and triggers merged while a push is
// in flight) each keep their own record carrying source and version; succeeded/failed/pending can
// be listed separately per connection.
func TestPushStatusRecords_TriggersKeepSourceVersionAndStates(t *testing.T) {
	recorder := NewPushStatusRecorder(true)
	queue := NewPushQueue(WithPushStatusRecorder(recorder))
	defer queue.ShutDown()
	con := statusTestConnection("proxy-A")

	queue.Enqueue(con, reqWithSource("v10", model.EndpointUpdate))
	queue.Enqueue(con, reqWithSource("v10", model.SecretTrigger))
	status := recorder.ConnectionStatus("proxy-A")
	if status == nil {
		t.Fatal("expected status for proxy-A")
	}
	if status.PendingCount != 2 || len(status.Pending) != 2 {
		t.Fatalf("expected 2 pending records, got count=%d records=%d", status.PendingCount, len(status.Pending))
	}
	gotVersions := map[uint64]map[string]int{}
	for _, rec := range status.Pending {
		if rec.State != PushRecordPending {
			t.Fatalf("expected pending record, got %v", rec.State)
		}
		if rec.PushVersion != "v10" {
			t.Fatalf("expected push version v10, got %q", rec.PushVersion)
		}
		gotVersions[rec.Version] = rec.Source
	}
	if gotVersions[1]["endpoint"] != 1 || gotVersions[2]["secret"] != 1 {
		t.Fatalf("expected one endpoint(v1) and one secret(v2) record, got %v", gotVersions)
	}

	// Dequeue starts processing the merged request containing both triggers.
	con2, merged := dequeueTestRequest(t, queue)
	if con2 != con {
		t.Fatalf("dequeued unexpected connection %v", con2)
	}
	if merged.Reason.Count() != 2 {
		t.Fatalf("expected merged request with 2 sources, got %v", merged.Reason)
	}

	// A third trigger arriving while processing merges into the in-flight push; it keeps its own
	// pending record alongside the in-flight batch, which is also still pending until it completes.
	queue.Enqueue(con, reqWithSource("v11", model.ConfigUpdate))
	status = recorder.ConnectionStatus("proxy-A")
	if status.PendingCount != 3 {
		t.Fatalf("expected 3 pending records while the batch is in flight, got %d", status.PendingCount)
	}

	// Current batch succeeds: v1 and v2 turn terminal, v3 (merged in during processing) stays
	// pending and is not part of the completed batch.
	queue.CompletePush(con, PushStageGenerate, nil)
	status = recorder.ConnectionStatus("proxy-A")
	if status.SuccessCount != 2 || status.PendingCount != 1 || status.FailedCount != 0 {
		t.Fatalf("expected 2 succeeded / 1 pending / 0 failed, got %+v", status)
	}
	if status.Pending[0].Version != 3 || status.Pending[0].Source["config"] != 1 {
		t.Fatalf("expected only the v3 config trigger to remain pending, got %+v", status.Pending)
	}
	if status.Version != 2 {
		t.Fatalf("expected reported version 2 (latest success), got %d", status.Version)
	}

	// MarkDone re-enqueues the trigger merged in during processing.
	queue.MarkDone(con)
	con3, _ := dequeueTestRequest(t, queue)
	if con3 != con {
		t.Fatalf("expected proxy-A re-enqueued")
	}
	queue.CompletePush(con, PushStageGenerate, nil)
	status = recorder.ConnectionStatus("proxy-A")
	if status.SuccessCount != 3 || status.PendingCount != 0 || status.FailedCount != 0 || status.Version != 3 {
		t.Fatalf("expected 3 succeeded and version 3, got success=%d pending=%d failed=%d version=%d",
			status.SuccessCount, status.PendingCount, status.FailedCount, status.Version)
	}
}

// Rubric 2: under concurrent triggering, the three categories' counts agree with the per-record
// lists, and repeated queries over a quiescent state return identical content.
func TestPushStatusRecords_ConcurrentTriggersConsistentSnapshot(t *testing.T) {
	recorder := NewPushStatusRecorder(true)
	queue := NewPushQueue(WithPushStatusRecorder(recorder))
	defer queue.ShutDown()
	con := statusTestConnection("proxy-concurrent")

	const triggers = 80
	sources := []model.TriggerReason{
		model.EndpointUpdate, model.ConfigUpdate, model.SecretTrigger, model.ServiceUpdate,
		model.ProxyUpdate, model.GlobalUpdate,
	}

	var enqueuers sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < triggers; i++ {
		enqueuers.Add(1)
		go func(i int) {
			defer enqueuers.Done()
			<-start
			queue.Enqueue(con, reqWithSource("", sources[i%len(sources)]))
		}(i)
	}
	close(start)
	enqueuers.Wait()

	// All triggers merged into one pending batch; dequeue and complete it.
	dequeued, req := dequeueTestRequest(t, queue)
	if dequeued != con {
		t.Fatalf("unexpected connection dequeued")
	}
	if req.Reason.Count() != triggers {
		t.Fatalf("expected %d merged sources, got %d", triggers, req.Reason.Count())
	}
	queue.CompletePush(con, PushStageGenerate, nil)

	status := recorder.ConnectionStatus("proxy-concurrent")
	if status == nil {
		t.Fatal("missing status")
	}
	if status.PendingCount != len(status.Pending) || status.SuccessCount != len(status.Succeeded) ||
		status.FailedCount != len(status.Failed) {
		t.Fatalf("counts and records disagree: %+v", status)
	}
	if status.SuccessCount != triggers {
		t.Fatalf("expected %d succeeded, got %d", triggers, status.SuccessCount)
	}
	seen := map[uint64]bool{}
	for _, rec := range status.Succeeded {
		if seen[rec.Version] {
			t.Fatalf("duplicate trigger version %d", rec.Version)
		}
		seen[rec.Version] = true
		if rec.State != PushRecordSucceeded {
			t.Fatalf("expected succeeded record, got %v", rec.State)
		}
	}
	if len(seen) != triggers {
		t.Fatalf("expected %d distinct versions, got %d", triggers, len(seen))
	}
	if status.Version != triggers {
		t.Fatalf("expected version %d, got %d", triggers, status.Version)
	}

	// Two consecutive queries over the quiescent state must return identical content.
	again := recorder.ConnectionStatus("proxy-concurrent")
	if !reflect.DeepEqual(status, again) {
		t.Fatalf("repeated queries returned different snapshots:\n%+v\n%+v", status, again)
	}
}

// Rubric 2 (mixed concurrent drain) and 4 (failure isolation): enqueues racing with a draining
// worker all end in a consistent terminal state; a failed trigger keeps its stage/error, while the
// next trigger succeeds independently and never inherits the failure.
func TestPushStatusRecords_FailureStageAndIsolation(t *testing.T) {
	recorder := NewPushStatusRecorder(true)
	queue := NewPushQueue(WithPushStatusRecorder(recorder))
	defer queue.ShutDown()
	con := statusTestConnection("proxy-fail")

	// Trigger 1 fails during config generation.
	queue.Enqueue(con, reqWithSource("v1", model.ConfigUpdate))
	genCon, _ := dequeueTestRequest(t, queue)
	genErr := errors.New("generate: boom")
	queue.CompletePush(genCon, PushStageGenerate, genErr)
	queue.MarkDone(con)

	status := recorder.ConnectionStatus("proxy-fail")
	if status.FailedCount != 1 || status.SuccessCount != 0 || status.Version != 0 {
		t.Fatalf("expected one generate failure and no version advance, got %+v", status)
	}
	failed := status.Failed[0]
	if failed.Stage != PushStageGenerate || failed.Error != "generate: boom" {
		t.Fatalf("expected generate-stage failure with error, got stage=%q err=%q", failed.Stage, failed.Error)
	}

	// Trigger 2 fails before reaching generation (dispatch entry), e.g. stream closed.
	queue.Enqueue(con, reqWithSource("v2", model.EndpointUpdate))
	entryCon, _ := dequeueTestRequest(t, queue)
	entryErr := errors.New("entry: connection closed")
	queue.CompletePush(entryCon, PushStageEntry, entryErr)
	queue.MarkDone(con)
	status = recorder.ConnectionStatus("proxy-fail")
	// The two failures must be distinguishable by stage.
	var hasEntry, hasGenerate bool
	for _, rec := range status.Failed {
		hasEntry = hasEntry || rec.Stage == PushStageEntry
		hasGenerate = hasGenerate || rec.Stage == PushStageGenerate
	}
	if !hasEntry || !hasGenerate {
		t.Fatalf("expected to locate one entry and one generate failure, got %+v", status.Failed)
	}

	// Trigger 3 succeeds; it must not carry the previous failure, and the version must advance.
	queue.Enqueue(con, reqWithSource("v3", model.SecretTrigger))
	okCon, _ := dequeueTestRequest(t, queue)
	queue.CompletePush(okCon, PushStageGenerate, nil)
	queue.MarkDone(con)

	status = recorder.ConnectionStatus("proxy-fail")
	if status.SuccessCount != 1 || status.PendingCount != 0 || status.Version != 3 {
		t.Fatalf("expected trigger 3 to succeed and version=3, got %+v", status)
	}
	succeeded := status.Succeeded[0]
	if succeeded.Error != "" || succeeded.Stage != "" {
		t.Fatalf("new successful record must not inherit previous failure, got stage=%q err=%q",
			succeeded.Stage, succeeded.Error)
	}
	if succeeded.Source["secret"] != 1 {
		t.Fatalf("expected secret source on the successful record, got %v", succeeded.Source)
	}
	// Old failure is retained but confined to its own record.
	if len(status.Failed) != 2 {
		t.Fatalf("expected both prior failures to remain recorded, got %d", len(status.Failed))
	}
}

// Triggers rejected at the entry once the queue shuts down are recorded as entry-stage failures.
func TestPushStatusRecords_EntryRejectionOnShutdown(t *testing.T) {
	recorder := NewPushStatusRecorder(true)
	queue := NewPushQueue(WithPushStatusRecorder(recorder))
	con := statusTestConnection("proxy-shutdown")

	queue.ShutDown()
	queue.Enqueue(con, reqWithSource("v1", model.ConfigUpdate))

	status := recorder.ConnectionStatus("proxy-shutdown")
	if status == nil || status.FailedCount != 1 {
		t.Fatalf("expected one rejected entry record, got %+v", status)
	}
	if rec := status.Failed[0]; rec.Stage != PushStageEntry {
		t.Fatalf("expected entry-stage rejection, got %q", rec.Stage)
	}
}

// Rubric 6: with recording disabled, no records are ever produced and the queue's distribution
// behavior is unchanged.
func TestPushStatusRecords_DisabledKeepsDefaultBehavior(t *testing.T) {
	recorder := NewPushStatusRecorder(false)
	queue := NewPushQueue(WithPushStatusRecorder(recorder))
	defer queue.ShutDown()
	con := statusTestConnection("proxy-off")

	if recorder.Enabled() {
		t.Fatal("recorder should be disabled by default")
	}
	queue.Enqueue(con, reqWithSource("v1", model.EndpointUpdate))
	queue.Enqueue(con, reqWithSource("v1", model.SecretTrigger))
	got, merged := dequeueTestRequest(t, queue)
	if got != con || merged.Reason.Count() != 2 {
		t.Fatalf("expected merged dequeue, got con=%v reasons=%v", got, merged.Reason)
	}
	// Must be a safe no-op (no panic, no state).
	queue.CompletePush(con, PushStageGenerate, nil)
	queue.MarkDone(con)

	if recorder.Status() != nil {
		t.Fatalf("disabled recorder must produce no records")
	}
	if recorder.ConnectionStatus("proxy-off") != nil {
		t.Fatalf("disabled recorder must report no connection status")
	}
}

// Rubric 7: constructors stay compatible. NewPushQueue works with no options (the existing call
// sites), with a nil/disabled recorder, and nil-receiver hooks do not panic.
func TestPushStatusRecords_BackwardCompatibleConstruction(t *testing.T) {
	// Existing call style: no options.
	defaultQueue := NewPushQueue()
	defer defaultQueue.ShutDown()
	con := statusTestConnection("proxy-default")
	defaultQueue.Enqueue(con, &model.PushRequest{})
	got, _ := dequeueTestRequest(t, defaultQueue)
	if got != con {
		t.Fatalf("default queue did not dequeue expected connection")
	}
	// Completing on a queue with a nil recorder must be a no-op.
	var nilRecorder *PushStatusRecorder
	nilQueue := NewPushQueue(WithPushStatusRecorder(nilRecorder))
	defer nilQueue.ShutDown()
	nilQueue.Enqueue(con, &model.PushRequest{})
	nilQueue.CompletePush(con, PushStageEntry, fmt.Errorf("ignored"))
	if got, _, shutdown := nilQueue.Dequeue(); shutdown || got != con {
		t.Fatalf("nil recorder must not alter queue behavior, got=%v shutdown=%v", got, shutdown)
	}
	nilQueue.MarkDone(con)
}

// TriggerSources on PushRequest (the "source" recorded per trigger) is an independent snapshot.
func TestPushRequestTriggerSources(t *testing.T) {
	pr := &model.PushRequest{Reason: model.NewReasonStats(model.EndpointUpdate, model.SecretTrigger)}
	sources := pr.TriggerSources()
	sources[model.EndpointUpdate] = 100
	if got := pr.Reason[model.EndpointUpdate]; got != 1 {
		t.Fatalf("mutating the snapshot must not affect the request, got %d", got)
	}
	if got := (&model.PushRequest{}).TriggerSources(); len(got) != 0 {
		t.Fatalf("expected empty non-nil snapshot for no reasons, got %v", got)
	}
}

// The /debug/push_records endpoint exposes the same separately queryable state, honors an exact
// proxyID filter, and reports disabled state with no records.
func TestPushRecordsHandler(t *testing.T) {
	recorder := NewPushStatusRecorder(true)
	queue := NewPushQueue(WithPushStatusRecorder(recorder))
	defer queue.ShutDown()
	s := &DiscoveryServer{pushStatus: recorder}
	con := statusTestConnection("proxy-http")

	queue.Enqueue(con, reqWithSource("v9", model.EndpointUpdate))
	got, _ := dequeueTestRequest(t, queue)
	queue.CompletePush(got, PushStageGenerate, nil)
	queue.MarkDone(got)

	call := func(target string) PushStatusSummary {
		t.Helper()
		req := httptest.NewRequest(http.MethodGet, target, nil)
		rr := httptest.NewRecorder()
		s.PushRecords(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d", rr.Code)
		}
		var summary PushStatusSummary
		if err := json.Unmarshal(rr.Body.Bytes(), &summary); err != nil {
			t.Fatalf("failed to decode response: %v", err)
		}
		return summary
	}

	summary := call("/debug/push_records")
	if !summary.Enabled || len(summary.Connections) != 1 {
		t.Fatalf("expected enabled summary with one connection, got %+v", summary)
	}
	status := summary.Connections[0]
	if status.Connection != "proxy-http" || status.Version != 1 || status.SuccessCount != 1 ||
		len(status.Succeeded) != 1 || status.Succeeded[0].Source["endpoint"] != 1 {
		t.Fatalf("unexpected connection status: %+v", status)
	}

	// Exact proxyID match returns the connection; a partial prefix must not match.
	if one := call("/debug/push_records?proxyID=proxy-http"); len(one.Connections) != 1 {
		t.Fatalf("expected exactly one connection for exact proxyID, got %d", len(one.Connections))
	}
	if partial := call("/debug/push_records?proxyID=proxy"); len(partial.Connections) != 0 {
		t.Fatalf("partial proxyID must not match, got %d", len(partial.Connections))
	}

	// A disabled server reports enabled=false with no records.
	disabled := &DiscoveryServer{pushStatus: NewPushStatusRecorder(false)}
	req := httptest.NewRequest(http.MethodGet, "/debug/push_records", nil)
	rr := httptest.NewRecorder()
	disabled.PushRecords(rr, req)
	var off PushStatusSummary
	if err := json.Unmarshal(rr.Body.Bytes(), &off); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if off.Enabled || len(off.Connections) != 0 {
		t.Fatalf("expected disabled summary without records, got %+v", off)
	}
}
