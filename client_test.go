package cloudflare

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"path"
	"testing"

	"github.com/libdns/libdns"
)

// fakeClient returns a fixed response body for every request, so getDNSRecords'
// TXT matching can be exercised deterministically without network or creds.
type fakeClient struct{ body string }

func (f fakeClient) Do(req *http.Request) (*http.Response, error) {
	return &http.Response{
		StatusCode: 200,
		Body:       io.NopCloser(bytes.NewBufferString(f.body)),
		Header:     make(http.Header),
	}, nil
}

func TestGetDNSRecordsTXTMatching(t *testing.T) {
	// Two TXT records at the same name with distinct decoded values.
	const body = `{"success":true,"result":[` +
		`{"id":"a","type":"TXT","name":"foo.example.com","content":"\"hello\""},` +
		`{"id":"b","type":"TXT","name":"foo.example.com","content":"\"world\""}` +
		`]}`
	p := &Provider{APIToken: "test", HTTPClient: fakeClient{body: body}}
	zone := cfZone{ID: "zone123", Name: "example.com"}
	ctx := context.Background()

	cases := []struct {
		name    string
		text    string
		wantIDs []string
	}{
		{"specific-match", "hello", []string{"a"}},
		{"other-specific-match", "world", []string{"b"}},
		{"empty-matches-all", "", []string{"a", "b"}}, // libdns empty-value contract
		{"no-match", "nope", nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := p.getDNSRecords(ctx, zone, libdns.TXT{Name: "foo", Text: c.text}, true)
			if err != nil {
				t.Fatalf("getDNSRecords: %v", err)
			}
			var ids []string
			for _, r := range got {
				ids = append(ids, r.ID)
			}
			if !equalStrings(ids, c.wantIDs) {
				t.Fatalf("text=%q: want IDs %v, got %v", c.text, c.wantIDs, ids)
			}
		})
	}
}

func TestGetDNSRecordsTXTMatchingMalformed(t *testing.T) {
	// A candidate whose stored content cannot be decoded (here, an unterminated
	// quoted string) must surface an error rather than be silently skipped.
	const body = `{"success":true,"result":[` +
		`{"id":"x","type":"TXT","name":"foo.example.com","content":"\"abc"}` +
		`]}`
	p := &Provider{APIToken: "test", HTTPClient: fakeClient{body: body}}
	zone := cfZone{ID: "zone123", Name: "example.com"}
	ctx := context.Background()

	// Non-empty value forces a decode, which must fail loudly.
	if _, err := p.getDNSRecords(ctx, zone, libdns.TXT{Name: "foo", Text: "abc"}, true); err == nil {
		t.Fatal("expected error for malformed TXT content, got nil")
	}

	// Empty value ("match any") never decodes, so it still matches the
	// undecodable record without error.
	got, err := p.getDNSRecords(ctx, zone, libdns.TXT{Name: "foo"}, true)
	if err != nil {
		t.Fatalf("empty-value match should not decode: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("empty-value match: want 1, got %d", len(got))
	}
}

func equalStrings(a, b []string) bool {
	// FIXME: replace with slices.Equal in go >= 1.21.
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// Records every request as "<METHOD> <id-or-query>"
type recordingClient struct {
	list     string
	requests []string
}

func (c *recordingClient) Do(req *http.Request) (*http.Response, error) {
	id := path.Base(req.URL.Path)
	var result string
	switch req.Method {
	case http.MethodGet:
		c.requests = append(c.requests, "GET "+req.URL.RawQuery)
		result = c.list
	case http.MethodDelete:
		c.requests = append(c.requests, "DELETE "+id)
		result = `{"id":"` + id + `"}`
	}
	return &http.Response{
		StatusCode: 200,
		Body:       io.NopCloser(bytes.NewBufferString(`{"success":true,"result":` + result + `}`)),
		Header:     make(http.Header),
	}, nil
}

func newRecordingProvider(list string) (*Provider, *recordingClient) {
	client := &recordingClient{list: list}
	p := &Provider{
		APIToken:   "test",
		HTTPClient: client,
		zones:      map[string]cfZone{"example.com.": {ID: "zone123", Name: "example.com"}},
	}
	return p, client
}

const threeARecords = `[` +
	`{"id":"a","type":"A","name":"foo.example.com","content":"192.0.2.1"},` +
	`{"id":"b","type":"A","name":"foo.example.com","content":"192.0.2.2"},` +
	`{"id":"c","type":"A","name":"foo.example.com","content":"192.0.2.3"}` +
	`]`

func TestDeleteRecordsEmptyValueDeletesAll(t *testing.T) {
	p, client := newRecordingProvider(threeARecords)

	deleted, err := p.DeleteRecords(context.Background(), "example.com.", []libdns.Record{
		libdns.RR{Name: "foo", Type: "A"},
	})
	if err != nil {
		t.Fatalf("DeleteRecords: %v", err)
	}
	if len(deleted) != 3 {
		t.Fatalf("want 3 deleted records, got %d", len(deleted))
	}
	want := []string{
		"GET name=foo.example.com&type=A", // no content.exact filter
		"DELETE a",
		"DELETE b",
		"DELETE c",
	}
	if !equalStrings(client.requests, want) {
		t.Fatalf("want requests %q, got %q", want, client.requests)
	}
}
