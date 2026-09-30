package cloudflare

import (
	"encoding/json"
	"net/netip"
	"strings"
	"testing"

	"github.com/libdns/libdns"
)

// An SRV record with priority 0 and weight 0 is common (e.g. "0 0 443 host."),
// and Cloudflare answers HTTP 400 "weight is a required data field" if the
// zero values are left out of the request body.
func TestCloudflareRecordSRVSendsZeroFields(t *testing.T) {
	cfRec, err := cloudflareRecord(libdns.SRV{
		Service:   "autodiscover",
		Transport: "tcp",
		Name:      "@",
		Priority:  0,
		Weight:    0,
		Port:      443,
		Target:    "mail.example.com.",
	})
	if err != nil {
		t.Fatalf("cloudflareRecord: %v", err)
	}
	body, err := json.Marshal(cfRec)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	for _, want := range []string{`"priority":0`, `"weight":0`, `"port":443`} {
		if !strings.Contains(string(body), want) {
			t.Errorf("request body missing %s: %s", want, body)
		}
	}
}

// Cloudflare answers HTTP 400 "priority is a required field" for an MX record
// whose preference 0 is left out of the request body.
func TestCloudflareRecordMXSendsZeroPriority(t *testing.T) {
	cfRec, err := cloudflareRecord(libdns.MX{Name: "@", Preference: 0, Target: "mail.example.com."})
	if err != nil {
		t.Fatalf("cloudflareRecord: %v", err)
	}
	body, err := json.Marshal(cfRec)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	var top map[string]any
	if err := json.Unmarshal(body, &top); err != nil {
		t.Fatalf("json.Unmarshal: %v", err)
	}
	if top["priority"] != float64(0) {
		t.Errorf(`request body missing top-level "priority":0: %s`, body)
	}
}

// Record types without a top-level priority must not gain one.
func TestCloudflareRecordOmitsPriorityForOtherTypes(t *testing.T) {
	cfRec, err := cloudflareRecord(libdns.Address{Name: "www", IP: netip.MustParseAddr("192.0.2.1")})
	if err != nil {
		t.Fatalf("cloudflareRecord: %v", err)
	}
	body, err := json.Marshal(cfRec)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	var top map[string]any
	if err := json.Unmarshal(body, &top); err != nil {
		t.Fatalf("json.Unmarshal: %v", err)
	}
	if _, ok := top["priority"]; ok {
		t.Errorf("request body has a spurious top-level priority: %s", body)
	}
}
