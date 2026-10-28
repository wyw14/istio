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

// Package baseline implements the "istioctl analyze" diagnostic baseline
// feature: exporting a snapshot of the diagnostics currently reported by the
// analyzers and, on later runs, classifying diagnostics as known (identical to
// an unexpired baseline entry), new, disappeared or expired. Only diagnostics
// that are not accepted by the baseline drive the analyze failure threshold.
package baseline

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"sigs.k8s.io/yaml"

	"istio.io/istio/pkg/config/analysis/diag"
)

const (
	// Version is the supported baseline file format version.
	Version = "v1alpha1"

	// header is written at the top of every exported baseline file.
	header = "# Istio analyze diagnostic baseline. Do not edit by hand unless you know what you are doing;\n" +
		"# re-export with `istioctl analyze --baseline-export <file>` to refresh it.\n"
)

// Baseline is the on-disk diagnostic baseline document.
type Baseline struct {
	// Version is the file format version; currently "v1alpha1".
	Version string `json:"version"`

	// Created is the UTC time the baseline was exported.
	Created time.Time `json:"created,omitempty"`

	// Entries are the accepted diagnostics.
	Entries []Entry `json:"entries"`
}

// Entry identifies a single diagnostic accepted by the baseline.
type Entry struct {
	// Code is the diagnostic message code, e.g. "IST0103".
	Code string `json:"code"`

	// Level is the severity of the diagnostic at export time, e.g. "Warning".
	// An entry never masks a diagnostic whose severity changed, so an upgrade
	// to Error is reported as a new diagnostic.
	Level string `json:"level"`

	// Resource is the stable identity of the resource the diagnostic refers
	// to, in the same form used by --suppress (e.g. "Pod mypod.testing").
	Resource string `json:"resource"`

	// Cluster is the cluster ID the resource belongs to. The empty string
	// denotes the local cluster or a file-only analysis.
	Cluster string `json:"cluster,omitempty"`

	// Parameters holds the positional message parameters, in order. Line
	// numbers and file positions are deliberately not part of an entry.
	Parameters []any `json:"parameters,omitempty"`

	// ExpiresAt optionally marks the UTC instant after which the entry stops
	// accepting diagnostics. A zero/nil value means the entry never expires.
	ExpiresAt *time.Time `json:"expiresAt,omitempty"`
}

// FileError represents a failure reading or parsing a baseline file. It is a
// data error (as opposed to a usage error) and must be surfaced clearly: a
// malformed baseline must never silently behave like an empty baseline.
type FileError struct {
	Path string
	Err  error
}

func (e *FileError) Error() string {
	if e.Path == "" {
		return fmt.Sprintf("invalid diagnostic baseline: %v", e.Err)
	}
	return fmt.Sprintf("invalid diagnostic baseline file %q: %v", e.Path, e.Err)
}

func (e *FileError) Unwrap() error { return e.Err }

// Load reads, parses and validates the baseline file at path.
func Load(path string) (*Baseline, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, &FileError{Path: path, Err: err}
	}
	b, err := Parse(data)
	if err != nil {
		return nil, &FileError{Path: path, Err: err}
	}
	return b, nil
}

// Parse parses and validates the serialized baseline document.
func Parse(data []byte) (*Baseline, error) {
	if len(bytes.TrimSpace(data)) == 0 {
		return nil, fmt.Errorf("document is empty")
	}

	jsonData, err := yaml.YAMLToJSON(data)
	if err != nil {
		return nil, fmt.Errorf("could not parse YAML: %w", err)
	}

	var b Baseline
	dec := json.NewDecoder(bytes.NewReader(jsonData))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&b); err != nil {
		return nil, fmt.Errorf("could not parse baseline document: %w", err)
	}
	if dec.More() {
		return nil, fmt.Errorf("expected a single baseline document, found multiple")
	}

	if b.Version != Version {
		return nil, fmt.Errorf("unsupported baseline version %q, expected %q", b.Version, Version)
	}
	if len(b.Entries) == 0 {
		return nil, fmt.Errorf("baseline contains no entries")
	}

	validLevels := make(map[string]struct{}, len(diag.GetAllLevels()))
	for _, l := range diag.GetAllLevels() {
		validLevels[l.String()] = struct{}{}
	}

	seen := make(map[string]struct{}, len(b.Entries))
	for i := range b.Entries {
		e := &b.Entries[i]
		if strings.TrimSpace(e.Code) == "" {
			return nil, fmt.Errorf("entry #%d is missing a message code", i+1)
		}
		if _, ok := validLevels[e.Level]; !ok {
			return nil, fmt.Errorf("entry #%d (%s) has invalid level %q, valid values are %v",
				i+1, e.Code, e.Level, diag.GetAllLevelStrings())
		}
		id := strings.TrimSpace(e.Resource)
		if id == "" {
			return nil, fmt.Errorf("entry #%d (%s) is missing a resource identity; "+
				"diagnostics without a reliable resource identity can not be baselined", i+1, e.Code)
		}
		e.Resource = id
		if e.ExpiresAt != nil {
			utc := e.ExpiresAt.UTC()
			e.ExpiresAt = &utc
		}
		if _, err := canonicalParameters(e.Parameters); err != nil {
			return nil, fmt.Errorf("entry #%d (%s %s) has invalid parameters: %w", i+1, e.Code, e.Resource, err)
		}
		e.Parameters = canonicalizeParameters(e.Parameters)
		key, err := e.key()
		if err != nil {
			return nil, err
		}
		if _, dup := seen[key]; dup {
			return nil, fmt.Errorf("duplicate baseline entry for %s on resource %q", e.Code, e.Resource)
		}
		seen[key] = struct{}{}
	}

	return &b, nil
}

// WriteFile serializes the baseline and writes it to path atomically-ish via a
// direct write, failing clearly if the file cannot be created.
func WriteFile(path string, b *Baseline) error {
	out, err := Marshal(b)
	if err != nil {
		return err
	}
	if err := os.WriteFile(path, out, 0o644); err != nil {
		return fmt.Errorf("could not write baseline file %q: %w", path, err)
	}
	return nil
}

// Marshal serializes a baseline document as YAML.
func Marshal(b *Baseline) ([]byte, error) {
	body, err := yaml.Marshal(b)
	if err != nil {
		return nil, fmt.Errorf("could not serialize baseline: %w", err)
	}
	return append([]byte(header), body...), nil
}

// FromMessages builds a baseline from the given diagnostics. Diagnostics
// without a reliable resource identity are skipped (the returned count tells
// how many) because they must never be hidden by a baseline. Entries are
// de-duplicated and sorted so the file is stable across exports; message line
// numbers never participate in the identity, so several identical diagnostics
// differing only by line produce a single entry.
func FromMessages(msgs diag.Messages, now time.Time) (*Baseline, int) {
	b := &Baseline{
		Version: Version,
		Created: now.UTC(),
	}
	seen := make(map[string]struct{})
	skipped := 0
	for _, m := range msgs {
		e, ok := EntryFromMessage(m)
		if !ok {
			skipped++
			continue
		}
		k, _ := e.key()
		if _, dup := seen[k]; dup {
			continue
		}
		seen[k] = struct{}{}
		b.Entries = append(b.Entries, e)
	}
	sort.Slice(b.Entries, func(i, j int) bool {
		ki, _ := b.Entries[i].key()
		kj, _ := b.Entries[j].key()
		return ki < kj
	})
	return b, skipped
}

// EntryFromMessage derives the baseline entry for a single diagnostic. The
// boolean is false when the diagnostic has no reliable resource identity and
// therefore must not be accepted by a baseline.
func EntryFromMessage(m diag.Message) (Entry, bool) {
	k, ok := fingerprintOf(m)
	if !ok {
		return Entry{}, false
	}
	params := canonicalizeParameters(m.Parameters)
	if len(params) == 0 {
		params = nil
	}
	return Entry{
		Code:       k.code,
		Level:      k.level,
		Resource:   k.resource,
		Cluster:    k.cluster,
		Parameters: params,
	}, true
}

// Report is the result of comparing a baseline with the diagnostics of a run.
type Report struct {
	// New are diagnostics not accepted by the baseline (including severity
	// changes, expired entries and diagnostics without a resource identity).
	// Only these drive the analyze failure threshold.
	New diag.Messages

	// Known are diagnostics identical to an unexpired baseline entry.
	Known diag.Messages

	// Disappeared are unexpired baseline entries that no longer match any
	// current diagnostic.
	Disappeared []Entry

	// Expired are baseline entries whose ExpiresAt instant has passed. They
	// never accept diagnostics, even identical ones.
	Expired []Entry
}

// Classify compares the diagnostics of a run against the baseline, using now
// as the reference time for expiry decisions. Message ordering is irrelevant:
// matching is purely based on code, severity, resource identity, cluster and
// message parameters.
func Classify(b *Baseline, msgs diag.Messages, now time.Time) Report {
	now = now.UTC()
	var r Report

	active := make(map[string]Entry, len(b.Entries))
	for _, e := range b.Entries {
		if e.ExpiresAt != nil && !e.ExpiresAt.After(now) {
			r.Expired = append(r.Expired, e)
			continue
		}
		k, _ := e.key()
		active[k] = e
	}

	for _, m := range msgs {
		fp, ok := fingerprintOf(m)
		if ok {
			if _, matched := active[fp.string()]; matched {
				r.Known = append(r.Known, m)
				// Consume the entry: duplicated diagnostics (possible when the
				// only difference is a line number, which does not participate
				// in the fingerprint) must match one-for-one.
				delete(active, fp.string())
				continue
			}
		}
		// No reliable identity, no matching entry, severity change or an
		// expired entry: the diagnostic is treated as new and may fail the run.
		r.New = append(r.New, m)
	}

	for _, e := range active {
		r.Disappeared = append(r.Disappeared, e)
	}
	sortEntries(r.Disappeared)
	sortEntries(r.Expired)
	return r
}

func sortEntries(entries []Entry) {
	sort.Slice(entries, func(i, j int) bool {
		ki, _ := entries[i].key()
		kj, _ := entries[j].key()
		return ki < kj
	})
}

// String renders a compact, human-readable one-line description of an entry
// for summaries.
func (e Entry) String() string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "%s [%s]", e.Level, e.Code)
	if e.Cluster != "" {
		fmt.Fprintf(&sb, " [cluster-%s]", e.Cluster)
	}
	fmt.Fprintf(&sb, " %s", e.Resource)
	if len(e.Parameters) > 0 {
		if p, err := json.Marshal(e.Parameters); err == nil {
			fmt.Fprintf(&sb, " parameters=%s", string(p))
		}
	}
	if e.ExpiresAt != nil {
		fmt.Fprintf(&sb, " (expired at %s)", e.ExpiresAt.UTC().Format(time.RFC3339))
	}
	return sb.String()
}

// fingerprint is the order-independent identity of a diagnostic. It never
// contains line numbers, file names or presentation order.
type fingerprint struct {
	code       string
	level      string
	resource   string
	cluster    string
	parameters string
}

func (f fingerprint) string() string {
	return strings.Join([]string{f.code, f.level, f.cluster, f.resource, f.parameters}, "\x00")
}

func fingerprintOf(m diag.Message) (fingerprint, bool) {
	if m.Type == nil || m.Resource == nil || m.Resource.Origin == nil {
		return fingerprint{}, false
	}
	// FriendlyName has the form "<Kind> [<namespace>/]<name>", i.e. the same
	// stable resource identity used by --suppress. A resource without both a
	// kind and a name has no reliable identity and cannot be baselined.
	id := strings.TrimSpace(m.Resource.Origin.FriendlyName())
	parts := strings.SplitN(id, " ", 2)
	if len(parts) != 2 || parts[0] == "" || strings.TrimSpace(parts[1]) == "" {
		return fingerprint{}, false
	}
	params, err := canonicalParameters(m.Parameters)
	if err != nil {
		return fingerprint{}, false
	}
	return fingerprint{
		code:       m.Type.Code(),
		level:      m.Type.Level().String(),
		resource:   id,
		cluster:    m.Resource.Origin.ClusterName().String(),
		parameters: params,
	}, true
}

func (e Entry) key() (string, error) {
	params, err := canonicalParameters(e.Parameters)
	if err != nil {
		return "", err
	}
	return fingerprint{
		code:       e.Code,
		level:      e.Level,
		resource:   e.Resource,
		cluster:    e.Cluster,
		parameters: params,
	}.string(), nil
}

// canonicalParameters reduces message parameters to a canonical JSON string so
// that equal parameters compare equal regardless of their concrete Go type.
func canonicalParameters(in []any) (string, error) {
	if len(in) == 0 {
		return "", nil
	}
	buf, err := json.Marshal(canonicalizeParameters(in))
	if err != nil {
		return "", err
	}
	return string(buf), nil
}

// canonicalizeParameters converts message parameters to JSON-compatible
// values with deterministic, type-independent representations.
func canonicalizeParameters(in []any) []any {
	if len(in) == 0 {
		return nil
	}
	out := make([]any, 0, len(in))
	for _, p := range in {
		out = append(out, canonicalValue(p))
	}
	return out
}

func canonicalValue(v any) any {
	switch x := v.(type) {
	case nil, string, bool:
		return x
	case int:
		return x
	case int8:
		return int(x)
	case int16:
		return int(x)
	case int32:
		return int(x)
	case int64:
		return int(x)
	case uint:
		return x
	case uint8:
		return uint(x)
	case uint16:
		return uint(x)
	case uint32:
		return uint(x)
	case uint64:
		return uint(x)
	case float32:
		return float64(x)
	case float64:
		return x
	case json.Number:
		return x.String()
	case fmt.Stringer:
		return x.String()
	case error:
		return x.Error()
	case []any:
		out := make([]any, 0, len(x))
		for _, item := range x {
			out = append(out, canonicalValue(item))
		}
		return out
	case []string:
		out := make([]any, 0, len(x))
		for _, item := range x {
			out = append(out, item)
		}
		return out
	case map[string]any:
		out := make(map[string]any, len(x))
		for k, item := range x {
			out[k] = canonicalValue(item)
		}
		return out
	default:
		return fmt.Sprintf("%v", x)
	}
}
