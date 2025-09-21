package main

import (
	"os"
	"strings"
	"testing"

	"github.com/libdns/cloudflare"
	"github.com/libdns/libdns/libdnstest"
)

func TestCloudflareProvider(t *testing.T) {
	apiToken := os.Getenv("CLOUDFLARE_API_TOKEN")
	zoneToken := os.Getenv("CLOUDFLARE_ZONE_TOKEN")
	testZone := os.Getenv("CLOUDFLARE_TEST_ZONE")

	if apiToken == "" || testZone == "" {
		t.Skip("Skipping Cloudflare provider tests: CLOUDFLARE_API_TOKEN and/or CLOUDFLARE_TEST_ZONE environment variables must be set")
	}

	if !strings.HasSuffix(testZone, ".") {
		t.Fatal("We expect the test zone to to have trailing dot")
	}

	provider := &cloudflare.Provider{
		APIToken:  apiToken,
		ZoneToken: zoneToken, // optional
	}

	suite := libdnstest.NewTestSuite(provider, testZone)
	suite.RunTests(t)
}
