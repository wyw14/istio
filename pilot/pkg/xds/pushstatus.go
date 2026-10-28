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
	"errors"
	"sort"
	"sync"
	"time"

	"istio.io/istio/pilot/pkg/model"
)

// maxPushRecordsPerConnection bounds the per-connection record history so a long lived, frequently
// pushed connection cannot grow the status state without limit.
const maxPushRecordsPerConnection = 256

// PushRecordState is the outcome, or pending outcome, of a single push trigger.
type PushRecordState string

const (
	// PushRecordPending means the trigger has been accepted but has not completed yet. A trigger
	// may be pending because it is queued, merged into an in-flight push, or being dispatched.
	PushRecordPending PushRecordState = "PENDING"
	// PushRecordSucceeded means the trigger finished without an error.
	PushRecordSucceeded PushRecordState = "SUCCEEDED"
	// PushRecordFailed means the trigger finished with an error; the record carries the stage and error.
	PushRecordFailed PushRecordState = "FAILED"
)

// PushStage identifies where a failure happened. This lets consumers distinguish a trigger that
// never reached config generation (for example the connection closed while queued) from one that
// failed while generating or sending configuration.
type PushStage string

const (
	// PushStageEntry covers the dispatch entry: the trigger was enqueued and handed to a
	// connection, but no configuration was generated (queue shutdown, closed stream, etc.).
	PushStageEntry PushStage = "entry"
	// PushStageGenerate covers config generation and sending to the proxy (pushConnection/pushXds).
	PushStageGenerate PushStage = "generate"
)

// PushTriggerRecord is the state record of a single trigger (a single Enqueue call) for a
// connection. Triggers that the distribution queue merges into one pending/in-flight push still
// each get their own record.
type PushTriggerRecord struct {
	// Connection identifies the XDS connection (proxy) the trigger belongs to.
	Connection string `json:"connection"`
	// ID is the per-connection, monotonically increasing identifier of the trigger.
	ID uint64 `json:"id"`
	// Version is the trigger version. It is assigned when the trigger enters the queue and only
	// becomes the connection's reported version when the trigger completes successfully.
	Version uint64 `json:"version"`
	// PushVersion is the push context version carried by the request at enqueue time, if any.
	PushVersion string `json:"pushVersion,omitempty"`
	// Source records what triggered this push (endpoint, config, secret, proxy request, ...),
	// snapshotted at enqueue so later merges cannot mutate it.
	Source map[string]int `json:"source"`
	// State is PENDING, SUCCEEDED or FAILED.
	State PushRecordState `json:"state"`
	// Stage is set only for failed records; it locates the failure at the dispatch entry or
	// during config generation.
	Stage PushStage `json:"stage,omitempty"`
	// Error is set only for failed records and belongs to this trigger alone; it is never copied
	// onto later triggers.
	Error string `json:"error,omitempty"`
	// EnqueuedAt is when the trigger entered the distribution queue.
	EnqueuedAt time.Time `json:"enqueuedAt"`
	// FinishedAt is when the trigger reached a terminal state.
	FinishedAt time.Time `json:"finishedAt,omitempty"`
}

// PushConnectionStatus is a point-in-time, separately queryable view of the push trigger records
// for one connection. The counts and the listed records are computed from the same snapshot.
type PushConnectionStatus struct {
	// Connection identifies the XDS connection (proxy).
	Connection string `json:"connection"`
	// Version is the version of the most recent SUCCESSFUL trigger for the connection. It does not
	// advance for failed or still-pending triggers.
	Version uint64 `json:"version"`
	// PendingCount/SuccessCount/FailedCount match the number of entries in the corresponding lists.
	PendingCount int `json:"pendingCount"`
	SuccessCount int `json:"succeededCount"`
	FailedCount  int `json:"failedCount"`
	// Pending, Succeeded and Failed list the individual records of each category.
	Pending   []PushTriggerRecord `json:"pending"`
	Succeeded []PushTriggerRecord `json:"succeeded"`
	Failed    []PushTriggerRecord `json:"failed"`
}

// PushStatusSummary is the JSON view returned by the /debug/push_records endpoint.
type PushStatusSummary struct {
	Enabled     bool                   `json:"enabled"`
	Connections []PushConnectionStatus `json:"connections"`
}

// pushBatch identifies the set of trigger records handed to one dequeue/processing round.
type pushBatch struct {
	connection string
	records    []uint64
}

type pushConnectionState struct {
	// nextVersion assigns per-connection, gap-free trigger versions (starting at 1).
	nextVersion uint64
	// lastSucceededVersion is the version of the latest successful trigger.
	lastSucceededVersion uint64
	// records retains triggers in enqueue order; bounded by trimRecords.
	records []*PushTriggerRecord
}

// PushStatusRecorder keeps per-connection push trigger records. All methods are safe for
// concurrent use. The zero value and a recorder built with enabled=false are no-ops, so callers
// never have to branch on whether recording is enabled.
type PushStatusRecorder struct {
	enabled bool

	mu    sync.RWMutex
	conns map[string]*pushConnectionState
	// inFlight holds the trigger record IDs being processed for a connection. The distribution
	// queue processes at most one batch per connection at a time.
	inFlight map[string]*pushBatch
}

// NewPushStatusRecorder creates a recorder. When enabled is false every method is a no-op and no
// state is ever allocated beyond the recorder itself, preserving the default distribution behavior.
func NewPushStatusRecorder(enabled bool) *PushStatusRecorder {
	if !enabled {
		return &PushStatusRecorder{enabled: false}
	}
	return &PushStatusRecorder{
		enabled:  true,
		conns:    make(map[string]*pushConnectionState),
		inFlight: make(map[string]*pushBatch),
	}
}

// Enabled reports whether record keeping is switched on.
func (r *PushStatusRecorder) Enabled() bool {
	return r != nil && r.enabled
}

func (r *PushStatusRecorder) stateFor(connection string) *pushConnectionState {
	st := r.conns[connection]
	if st == nil {
		st = &pushConnectionState{}
		r.conns[connection] = st
	}
	return st
}

func triggerKey(con *Connection) string {
	if id := con.ID(); id != "" {
		return id
	}
	return con.Peer()
}

// RecordEnqueue appends one PENDING record for a trigger entering the queue. It is called on every
// Enqueue, including triggers that the queue merges into a pending or in-flight push, so each
// trigger retains its own source and version.
//
// RecordEnqueue is invoked with the PushQueue lock held.
func (r *PushStatusRecorder) RecordEnqueue(con *Connection, request *model.PushRequest) {
	if !r.Enabled() {
		return
	}
	connection := triggerKey(con)
	now := time.Now()
	r.mu.Lock()
	defer r.mu.Unlock()
	st := r.stateFor(connection)
	st.nextVersion++
	st.records = append(st.records, &PushTriggerRecord{
		Connection:  connection,
		ID:          st.nextVersion,
		Version:     st.nextVersion,
		PushVersion: pushVersionOf(request),
		Source:      copySources(request),
		State:       PushRecordPending,
		EnqueuedAt:  now,
	})
	r.trimRecordsLocked(st)
}

// RecordEntryRejected records a trigger that was refused at the dispatch entry (for example the
// queue was already shutting down). It never enters PENDING and does not advance the version.
//
// RecordEntryRejected is invoked with the PushQueue lock held.
func (r *PushStatusRecorder) RecordEntryRejected(con *Connection, request *model.PushRequest, err error) {
	if !r.Enabled() {
		return
	}
	connection := triggerKey(con)
	now := time.Now()
	r.mu.Lock()
	defer r.mu.Unlock()
	st := r.stateFor(connection)
	st.nextVersion++
	rec := &PushTriggerRecord{
		Connection:  connection,
		ID:          st.nextVersion,
		Version:     st.nextVersion,
		PushVersion: pushVersionOf(request),
		Source:      copySources(request),
		State:       PushRecordFailed,
		Stage:       PushStageEntry,
		Error:       err.Error(),
		EnqueuedAt:  now,
		FinishedAt:  now,
	}
	st.records = append(st.records, rec)
	r.trimRecordsLocked(st)
}

// Start marks the currently pending triggers of a connection as the batch being processed and
// returns the batch. Triggers enqueued afterwards (for example ones merged into the in-flight
// push) remain PENDING and are picked up by the next Start.
//
// Start is invoked with the PushQueue lock held during Dequeue.
func (r *PushStatusRecorder) Start(con *Connection) *pushBatch {
	if !r.Enabled() {
		return nil
	}
	connection := triggerKey(con)
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.inFlight[connection]; exists {
		// A batch is still in flight; a new batch cannot start for this connection.
		return r.inFlight[connection]
	}
	st := r.conns[connection]
	if st == nil {
		return nil
	}
	batch := &pushBatch{connection: connection}
	for _, rec := range st.records {
		if rec.State == PushRecordPending {
			batch.records = append(batch.records, rec.ID)
		}
	}
	if len(batch.records) == 0 {
		return nil
	}
	r.inFlight[connection] = batch
	return batch
}

// Complete finalizes a processing round for the connection: all records of the in-flight batch
// become SUCCEEDED (err == nil) or FAILED with the given stage and error (err != nil). Only the
// records of this batch are touched, so a failure neither affects later, still-pending triggers
// nor leaks its error onto them. The connection version advances to the batch's latest trigger
// version only on success.
func (r *PushStatusRecorder) Complete(con *Connection, stage PushStage, err error) {
	if !r.Enabled() {
		return
	}
	connection := triggerKey(con)
	now := time.Now()
	r.mu.Lock()
	defer r.mu.Unlock()
	batch := r.inFlight[connection]
	if batch == nil {
		return
	}
	delete(r.inFlight, connection)

	terminal := PushRecordSucceeded
	errMsg := ""
	if err != nil {
		terminal = PushRecordFailed
		errMsg = err.Error()
	}
	st := r.conns[connection]
	if st == nil {
		return
	}
	byID := make(map[uint64]*PushTriggerRecord, len(st.records))
	for _, rec := range st.records {
		byID[rec.ID] = rec
	}
	var maxVersion uint64
	for _, id := range batch.records {
		rec := byID[id]
		if rec == nil {
			continue
		}
		rec.State = terminal
		rec.FinishedAt = now
		if err != nil {
			// Attach the stage and the error to this record only; each trigger owns its fields.
			rec.Stage = stage
			rec.Error = errMsg
		} else {
			rec.Stage = ""
			rec.Error = ""
			if rec.Version > maxVersion {
				maxVersion = rec.Version
			}
		}
	}
	if err == nil && maxVersion > st.lastSucceededVersion {
		st.lastSucceededVersion = maxVersion
	}
}

// DeleteConnection drops all record state of a connection. It is called when the XDS stream ends.
func (r *PushStatusRecorder) DeleteConnection(con *Connection) {
	if !r.Enabled() {
		return
	}
	connection := triggerKey(con)
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.conns, connection)
	delete(r.inFlight, connection)
}

// ConnectionStatus returns a consistent snapshot for one connection, with pending, succeeded and
// failed records listed separately. It returns nil if the connection is unknown (for example when
// recording is disabled or the connection never triggered a push).
func (r *PushStatusRecorder) ConnectionStatus(connection string) *PushConnectionStatus {
	if !r.Enabled() {
		return nil
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	st := r.conns[connection]
	if st == nil {
		return nil
	}
	return r.snapshotLocked(connection, st)
}

// Status returns a consistent snapshot for every connection with records, ordered by connection ID.
func (r *PushStatusRecorder) Status() []PushConnectionStatus {
	if !r.Enabled() {
		return nil
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	connections := make([]string, 0, len(r.conns))
	for connection := range r.conns {
		connections = append(connections, connection)
	}
	sort.Strings(connections)
	out := make([]PushConnectionStatus, 0, len(connections))
	for _, connection := range connections {
		out = append(out, *r.snapshotLocked(connection, r.conns[connection]))
	}
	return out
}

// snapshotLocked builds one PushConnectionStatus from a single read-locked view, so the three
// categories and their counts always agree and repeated queries over a quiescent state are equal.
func (r *PushStatusRecorder) snapshotLocked(connection string, st *pushConnectionState) *PushConnectionStatus {
	status := &PushConnectionStatus{
		Connection: connection,
		Version:    st.lastSucceededVersion,
		Pending:    make([]PushTriggerRecord, 0),
		Succeeded:  make([]PushTriggerRecord, 0),
		Failed:     make([]PushTriggerRecord, 0),
	}
	for _, rec := range st.records {
		copy := *rec
		copy.Source = cloneSources(rec.Source)
		switch rec.State {
		case PushRecordPending:
			status.Pending = append(status.Pending, copy)
		case PushRecordSucceeded:
			status.Succeeded = append(status.Succeeded, copy)
		case PushRecordFailed:
			status.Failed = append(status.Failed, copy)
		}
	}
	status.PendingCount = len(status.Pending)
	status.SuccessCount = len(status.Succeeded)
	status.FailedCount = len(status.Failed)
	return status
}

// trimRecordsLocked bounds the history, dropping oldest records first. Pending records (including
// the in-flight batch) are retained so an in-flight push can never lose its state.
func (r *PushStatusRecorder) trimRecordsLocked(st *pushConnectionState) {
	for len(st.records) > maxPushRecordsPerConnection {
		dropAt := -1
		for i, rec := range st.records {
			if rec.State != PushRecordPending {
				dropAt = i
				break
			}
		}
		if dropAt < 0 {
			// Only pending records remain; keep them rather than corrupting an active push.
			return
		}
		st.records = append(st.records[:dropAt], st.records[dropAt+1:]...)
	}
}

func pushVersionOf(request *model.PushRequest) string {
	if request == nil || request.Push == nil {
		return ""
	}
	return request.Push.PushVersion
}

func copySources(request *model.PushRequest) map[string]int {
	sources := request.TriggerSources()
	if len(sources) == 0 {
		return map[string]int{}
	}
	out := make(map[string]int, len(sources))
	for reason, count := range sources {
		out[string(reason)] = count
	}
	return out
}

func cloneSources(in map[string]int) map[string]int {
	if len(in) == 0 {
		return map[string]int{}
	}
	out := make(map[string]int, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

// errPushQueueShuttingDown is recorded for triggers rejected at the entry once the queue shuts down.
var errPushQueueShuttingDown = errors.New("push discarded: the push queue is shutting down")
