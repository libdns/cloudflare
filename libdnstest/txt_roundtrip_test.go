package main

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/libdns/cloudflare"
	"github.com/libdns/libdns"
)

// TestLongTXTRoundTrip exercises >255-byte, special-character, and raw-byte TXT
// values end-to-end against the live Cloudflare API: each must round-trip
// byte-exactly through Append -> Get and be removed by Delete.
func TestLongTXTRoundTrip(t *testing.T) {
	apiToken, testZone := txtTestEnv(t)
	provider := &cloudflare.Provider{APIToken: apiToken}
	ctx := context.Background()

	dkim := "v=DKIM1; k=rsa; p=" + strings.Repeat("MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA", 9) + "IDAQAB"
	cases := []struct{ name, text string }{
		{"test-txt-dkim._domainkey", dkim},
		{"test-txt-special", `has "quotes" and \back\slash`},
		{"test-txt-rawbytes", "\x00\x01\xfe\xff raw \x80\x7f bytes"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := libdns.TXT{Name: tc.name, TTL: 5 * time.Minute, Text: tc.text}

			_, _ = provider.DeleteRecords(ctx, testZone, []libdns.Record{rec})
			t.Cleanup(func() {
				_, _ = provider.DeleteRecords(ctx, testZone, []libdns.Record{rec})
			})

			if _, err := provider.AppendRecords(ctx, testZone, []libdns.Record{rec}); err != nil {
				t.Fatalf("AppendRecords: %v", err)
			}

			found, err := findTXT(ctx, provider, testZone, tc.name)
			if err != nil {
				t.Fatalf("GetRecords: %v", err)
			}
			if found == nil {
				t.Fatalf("record %q not found after append", tc.name)
			}
			if found.Text != tc.text {
				t.Fatalf("round-trip mismatch for %q:\n want %q\n got  %q", tc.name, tc.text, found.Text)
			}

			deleted, err := provider.DeleteRecords(ctx, testZone, []libdns.Record{rec})
			if err != nil {
				t.Fatalf("DeleteRecords: %v", err)
			}
			if len(deleted) != 1 {
				t.Fatalf("expected 1 deleted, got %d", len(deleted))
			}

			stillThere, err := findTXT(ctx, provider, testZone, tc.name)
			if err != nil {
				t.Fatalf("GetRecords after delete: %v", err)
			}
			if stillThere != nil {
				t.Fatalf("record %q still present after delete", tc.name)
			}
		})
	}
}

// TestDeleteTXTByEmptyText verifies the libdns RecordDeleter contract: a TXT
// record with an empty Text must delete any TXT at that name regardless of its
// value.
func TestDeleteTXTByEmptyText(t *testing.T) {
	apiToken, testZone := txtTestEnv(t)
	provider := &cloudflare.Provider{APIToken: apiToken}
	ctx := context.Background()

	const name = "test-txt-emptydel"
	full := libdns.TXT{Name: name, TTL: 5 * time.Minute, Text: "v=spf1 include:example.net -all"}

	// Clean up by the real value, not empty Text, so teardown doesn't depend on
	// the behavior under test.
	_, _ = provider.DeleteRecords(ctx, testZone, []libdns.Record{full})
	t.Cleanup(func() {
		_, _ = provider.DeleteRecords(ctx, testZone, []libdns.Record{full})
	})

	if _, err := provider.AppendRecords(ctx, testZone, []libdns.Record{full}); err != nil {
		t.Fatalf("AppendRecords: %v", err)
	}

	deleted, err := provider.DeleteRecords(ctx, testZone, []libdns.Record{libdns.TXT{Name: name}})
	if err != nil {
		t.Fatalf("DeleteRecords(empty Text): %v", err)
	}
	if len(deleted) != 1 {
		t.Fatalf("empty-Text delete: expected 1 deleted, got %d", len(deleted))
	}

	found, err := findTXT(ctx, provider, testZone, name)
	if err != nil {
		t.Fatalf("GetRecords after delete: %v", err)
	}
	if found != nil {
		t.Fatalf("record %q still present after empty-Text delete", name)
	}
}

// TestSetTXTRoundTrip confirms SetRecords creates and then updates a single
// long TXT record in place with byte-exact round-trip (the DKIM-rotation path).
func TestSetTXTRoundTrip(t *testing.T) {
	apiToken, testZone := txtTestEnv(t)
	provider := &cloudflare.Provider{APIToken: apiToken}
	ctx := context.Background()

	const name = "test-txt-set._domainkey"
	v1 := "v=DKIM1; k=rsa; p=" + strings.Repeat("MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA", 9) + "IDAQAB"
	v2 := "v=DKIM1; k=rsa; p=" + strings.Repeat("ZZZBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA", 7) + "IDAQAB"

	t.Cleanup(func() {
		_, _ = provider.DeleteRecords(ctx, testZone, []libdns.Record{libdns.TXT{Name: name, Text: v1}})
		_, _ = provider.DeleteRecords(ctx, testZone, []libdns.Record{libdns.TXT{Name: name, Text: v2}})
	})

	if _, err := provider.SetRecords(ctx, testZone, []libdns.Record{libdns.TXT{Name: name, TTL: 5 * time.Minute, Text: v1}}); err != nil {
		t.Fatalf("SetRecords (create): %v", err)
	}
	if got, err := findTXT(ctx, provider, testZone, name); err != nil {
		t.Fatalf("GetRecords after create: %v", err)
	} else if got == nil || got.Text != v1 {
		t.Fatalf("after create: want %q, got %+v", v1, got)
	}

	if _, err := provider.SetRecords(ctx, testZone, []libdns.Record{libdns.TXT{Name: name, TTL: 5 * time.Minute, Text: v2}}); err != nil {
		t.Fatalf("SetRecords (update): %v", err)
	}
	if got, err := findTXT(ctx, provider, testZone, name); err != nil {
		t.Fatalf("GetRecords after update: %v", err)
	} else if got == nil || got.Text != v2 {
		t.Fatalf("after update: want %q, got %+v", v2, got)
	}
	// The update must be in place, not a second record.
	if n := countTXT(ctx, t, provider, testZone, name); n != 1 {
		t.Fatalf("after update: expected exactly 1 TXT at %q, got %d", name, n)
	}
}

func countTXT(ctx context.Context, t *testing.T, p *cloudflare.Provider, zone, name string) int {
	t.Helper()
	recs, err := p.GetRecords(ctx, zone)
	if err != nil {
		t.Fatalf("GetRecords: %v", err)
	}
	n := 0
	for _, r := range recs {
		if txt, ok := r.(libdns.TXT); ok && txt.Name == name {
			n++
		}
	}
	return n
}

func txtTestEnv(t *testing.T) (apiToken, testZone string) {
	t.Helper()
	apiToken = os.Getenv("CLOUDFLARE_API_TOKEN")
	testZone = os.Getenv("CLOUDFLARE_TEST_ZONE")
	if apiToken == "" || testZone == "" {
		t.Skip("Skipping live TXT test: set CLOUDFLARE_API_TOKEN and CLOUDFLARE_TEST_ZONE")
	}
	if !strings.HasSuffix(testZone, ".") {
		t.Fatal("CLOUDFLARE_TEST_ZONE must have a trailing dot")
	}
	return apiToken, testZone
}

func findTXT(ctx context.Context, p *cloudflare.Provider, zone, name string) (*libdns.TXT, error) {
	recs, err := p.GetRecords(ctx, zone)
	if err != nil {
		return nil, err
	}
	for _, r := range recs {
		if txt, ok := r.(libdns.TXT); ok && txt.Name == name {
			return &txt, nil
		}
	}
	return nil, nil
}
