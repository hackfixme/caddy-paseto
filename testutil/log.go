package testutil

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"sync"
	"time"
)

// TestLogHandler is a slog.Handler implementation for testing that captures
// log records and allows inspection of their content.
type TestLogHandler struct {
	mu      sync.RWMutex
	records *[]TestLogRecord
	attrs   []slog.Attr
	groups  []string
}

// TestLogRecord represents a captured log record with its attributes.
type TestLogRecord struct {
	Time    time.Time     `json:"time"`
	Level   slog.Level    `json:"level"`
	Message string        `json:"message"`
	Attrs   []TestLogAttr `json:"attrs"`
	Groups  []string      `json:"groups,omitempty"`
}

// TestLogAttr represents an attribute with a resolved value for JSON serialization.
type TestLogAttr struct {
	Key   string `json:"key"`
	Value any    `json:"value"`
}

// NewTestLogHandler creates a new TestLogHandler.
func NewTestLogHandler() *TestLogHandler {
	records := make([]TestLogRecord, 0)
	return &TestLogHandler{
		records: &records,
	}
}

// Enabled returns true for all log levels.
func (h *TestLogHandler) Enabled(_ context.Context, _ slog.Level) bool {
	return true
}

// Handle captures the log record.
func (h *TestLogHandler) Handle(_ context.Context, r slog.Record) error {
	h.mu.Lock()
	defer h.mu.Unlock()

	var attrs []TestLogAttr

	// Add handler-level attributes
	for _, attr := range h.attrs {
		attrs = append(attrs, TestLogAttr{
			Key:   attr.Key,
			Value: resolveValue(attr.Value),
		})
	}

	// Add record-level attributes
	r.Attrs(func(a slog.Attr) bool {
		attrs = append(attrs, TestLogAttr{
			Key:   a.Key,
			Value: resolveValue(a.Value),
		})
		return true
	})

	record := TestLogRecord{
		Time:    r.Time,
		Level:   r.Level,
		Message: r.Message,
		Attrs:   attrs,
		Groups:  slices.Clone(h.groups),
	}

	*h.records = append(*h.records, record)
	return nil
}

// WithAttrs returns a new handler with additional attributes.
func (h *TestLogHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	h.mu.RLock()
	defer h.mu.RUnlock()

	return &TestLogHandler{
		records: h.records,
		attrs:   append(slices.Clone(h.attrs), attrs...),
		groups:  slices.Clone(h.groups),
	}
}

// WithGroup returns a new handler with an additional group.
func (h *TestLogHandler) WithGroup(name string) slog.Handler {
	if name == "" {
		return h
	}

	h.mu.RLock()
	defer h.mu.RUnlock()

	return &TestLogHandler{
		records: h.records,
		attrs:   slices.Clone(h.attrs),
		groups:  append(slices.Clone(h.groups), name),
	}
}

// Records returns all captured log records.
func (h *TestLogHandler) Records() []TestLogRecord {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return slices.Clone(*h.records)
}

// Clear removes all captured records.
func (h *TestLogHandler) Clear() {
	h.mu.Lock()
	defer h.mu.Unlock()
	*h.records = (*h.records)[:0]
}

// Count returns the number of captured records.
func (h *TestLogHandler) Count() int {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return len(*h.records)
}

// HasRecord checks if any record matches the given level and message.
func (h *TestLogHandler) HasRecord(level slog.Level, message string) bool {
	h.mu.RLock()
	defer h.mu.RUnlock()

	for _, record := range *h.records {
		if record.Level == level && strings.Contains(record.Message, message) {
			return true
		}
	}
	return false
}

// String returns a human-readable representation of all records.
func (h *TestLogHandler) String() string {
	h.mu.RLock()
	defer h.mu.RUnlock()

	if len(*h.records) == 0 {
		return "TestLogHandler: no records"
	}

	var buf strings.Builder
	buf.WriteString(fmt.Sprintf("TestLogHandler: %d record(s)\n", len(*h.records)))

	for i, record := range *h.records {
		buf.WriteString(fmt.Sprintf("[%d] %s %s: %s",
			i,
			record.Time.Format(time.RFC3339),
			record.Level,
			record.Message))

		if len(record.Groups) > 0 {
			buf.WriteString(fmt.Sprintf(" (groups: %s)", strings.Join(record.Groups, ".")))
		}

		if len(record.Attrs) > 0 {
			buf.WriteString(" {")
			for j, attr := range record.Attrs {
				if j > 0 {
					buf.WriteString(", ")
				}
				buf.WriteString(fmt.Sprintf("%s=%v", attr.Key, attr.Value))
			}
			buf.WriteString("}")
		}
		buf.WriteString("\n")
	}

	return buf.String()
}

// MarshalJSON implements json.Marshaler for serialization.
func (h *TestLogHandler) MarshalJSON() ([]byte, error) {
	h.mu.RLock()
	defer h.mu.RUnlock()

	return json.Marshal(map[string]any{
		"records": *h.records,
		"count":   len(*h.records),
	})
}

// resolveValue converts a slog.Value to its underlying Go value for JSON serialization.
func resolveValue(v slog.Value) any {
	switch v.Kind() {
	case slog.KindString:
		return v.String()
	case slog.KindInt64:
		return v.Int64()
	case slog.KindUint64:
		return v.Uint64()
	case slog.KindFloat64:
		return v.Float64()
	case slog.KindBool:
		return v.Bool()
	case slog.KindDuration:
		return v.Duration()
	case slog.KindTime:
		return v.Time()
	case slog.KindAny:
		return v.Any()
	case slog.KindLogValuer:
		// Resolve LogValuer and recurse
		return resolveValue(v.Resolve())
	case slog.KindGroup:
		// Handle nested groups
		attrs := v.Group()
		resolved := make(map[string]any)
		for _, attr := range attrs {
			resolved[attr.Key] = resolveValue(attr.Value)
		}
		return resolved
	default:
		return v.Any()
	}
}
