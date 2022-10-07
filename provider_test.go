package cloudflare

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/libdns/libdns"
)

const (
	TokenEnv = "CF_TOKEN"
	ZonesEnv = "CF_ZONE"
)

func setup(t *testing.T) (*Provider, string) {
	tk := os.Getenv(TokenEnv)
	zone := os.Getenv(ZonesEnv)
	if tk == "" || zone == "" {
		t.Skipf("Skipping test, missing %s or %s", TokenEnv, ZonesEnv)
	}
	return &Provider{APIToken: tk}, zone
}

func TestMailRecords(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	p, zone := setup(t)
	// defaultTTL is the cloudflare default TTL
	// it's not really a second as 1 means 'automatic'
	defaultTTL := time.Second

	tests := []struct {
		name    string
		rec     libdns.Record
		want    libdns.Record
		wantErr bool
	}{
		{
			name: "A record",
			rec: libdns.Record{
				Type:  "A",
				Name:  "",
				Value: "10.10.10.110",
			},
			want: libdns.Record{
				Type:  "A",
				Name:  "",
				Value: "10.10.10.110",
			},
		},
		{
			name: "CNAME record",
			rec: libdns.Record{
				Type:  "CNAME",
				Name:  "mail",
				Value: "@",
			},
			want: libdns.Record{
				Type:  "CNAME",
				Name:  "mail",
				Value: "",
			},
		},
		{
			name: "MX record",
			rec: libdns.Record{
				Type:  "MX",
				Name:  zone,
				Value: "10 mail." + zone,
			},
			want: libdns.Record{
				Type:  "MX",
				Name:  "",
				Value: "10 mail",
			},
		},
		{
			name: "MX record non canonical",
			rec: libdns.Record{
				Type:     "MX",
				Name:     zone,
				Value:    "mail." + zone,
				Priority: 10,
			},
			want: libdns.Record{
				Type:  "MX",
				Name:  "",
				Value: "10 mail",
			},
		},
		{
			name: "SRV imaps record",
			rec: libdns.Record{
				Type:  "SRV",
				Name:  "_imaps._tcp",
				Value: "10 10 993 mail." + zone,
			},
			want: libdns.Record{
				Type:  "SRV",
				Name:  "_imaps._tcp",
				Value: "10 10 993 mail",
			},
		},
		{
			name: "SRV submission record",
			rec: libdns.Record{
				Type:  "SRV",
				Name:  "_submission._tcp.@",
				Value: "10 10 587 mail." + zone,
			},
			want: libdns.Record{
				Type:  "SRV",
				Name:  "_submission._tcp",
				Value: "10 10 587 mail",
			},
		},
		{
			name: "TXT spf record",
			rec: libdns.Record{
				Type:  "TXT",
				Name:  "",
				Value: "v=spf1 a mx -all",
			},
			want: libdns.Record{
				Type:  "TXT",
				Name:  "",
				Value: "v=spf1 a mx -all",
			},
		},
		{
			name: "TXT dkim record",
			rec: libdns.Record{
				Type:  "TXT",
				Name:  "mail._domainkey." + zone,
				Value: "v=DKIM1; h=sha256; k=rsa; p=jANBgkqhkiG9w0BAQEFAAOSAg8AMIICCgKCAgEAoxTULRWLAevz5Q7pDE72xPVQ2zSmEabsyCof2EgHAzTzCgujadEzIKYFNpXgZsQ1euVR1D60j0Z9iLeubPPoxRXxlcSx+BoSB8uHW/yNpeRJwzuI46oGJvPEqcGxhVLZphsfecEkcKjMvHJCzt2UAoAmuedQJlNbwTz6NkZoEa5aac5HfDrvY4RCmgwvBF8tyWmJt5XYvk4M9G4Ktr134V0ahIlXKOAZv83SyMsCWHeCzU2hcsAY/uT7K4/torutMJKpiYK24GGk4Ce+MvCG89XwH5pHvBJ6dTO9QckOPz/nyTXGVEz/IJfnUkcnWvWqzCNiBbMF5F5hNGJjIjHn4iXttk+zRDHzo5LFfNiMNk88wxSKC+KuokvSNzHJSrsR6DCoFvTlbgC66N8RCjdklcm4fuPIWrtmyEob9pFOXg6GXRqbtK94HWOEOcQn5YzukKb8b6X1uLKGuqCZNvZZZECp5B4fMKrJBmW273MVg+2YIhoRmfhcIxoWvL3SVVuLKB1+ytdIfD8Qr30e/xNXSN4ZcdbtVwkXaqp1+/sp1fqq2KeEZJxftzChDNUpQ+GDxj0Xtfd2PicCsgemaOIslOKQIe7DZ5YBMRmZhT5OIRp8wJNOsZ3QbDpnlxCk8Ruh5dG0E21DREnkcXEAZjyv8gO0I2O7Ze6Vei2q3T94OecCAwEAAQ==",
				TTL:   60 * time.Second,
			},
			want: libdns.Record{
				Type:  "TXT",
				Name:  "mail._domainkey",
				Value: "v=DKIM1; h=sha256; k=rsa; p=jANBgkqhkiG9w0BAQEFAAOSAg8AMIICCgKCAgEAoxTULRWLAevz5Q7pDE72xPVQ2zSmEabsyCof2EgHAzTzCgujadEzIKYFNpXgZsQ1euVR1D60j0Z9iLeubPPoxRXxlcSx+BoSB8uHW/yNpeRJwzuI46oGJvPEqcGxhVLZphsfecEkcKjMvHJCzt2UAoAmuedQJlNbwTz6NkZoEa5aac5HfDrvY4RCmgwvBF8tyWmJt5XYvk4M9G4Ktr134V0ahIlXKOAZv83SyMsCWHeCzU2hcsAY/uT7K4/torutMJKpiYK24GGk4Ce+MvCG89XwH5pHvBJ6dTO9QckOPz/nyTXGVEz/IJfnUkcnWvWqzCNiBbMF5F5hNGJjIjHn4iXttk+zRDHzo5LFfNiMNk88wxSKC+KuokvSNzHJSrsR6DCoFvTlbgC66N8RCjdklcm4fuPIWrtmyEob9pFOXg6GXRqbtK94HWOEOcQn5YzukKb8b6X1uLKGuqCZNvZZZECp5B4fMKrJBmW273MVg+2YIhoRmfhcIxoWvL3SVVuLKB1+ytdIfD8Qr30e/xNXSN4ZcdbtVwkXaqp1+/sp1fqq2KeEZJxftzChDNUpQ+GDxj0Xtfd2PicCsgemaOIslOKQIe7DZ5YBMRmZhT5OIRp8wJNOsZ3QbDpnlxCk8Ruh5dG0E21DREnkcXEAZjyv8gO0I2O7Ze6Vei2q3T94OecCAwEAAQ==",
				TTL:   60 * time.Second,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			recs, err := p.SetRecords(ctx, zone, []libdns.Record{tt.rec})
			if err != nil {
				if !tt.wantErr {
					t.Errorf("SetRecords() error = %v, wantErr %v", err, tt.wantErr)
				}
				return
			}
			if len(recs) != 1 {
				t.Errorf("SetRecords() len = %d, want 1", len(recs))
			}
			if recs[0].ID == "" {
				t.Errorf("SetRecords() ID = %s, want not empty", recs[0].ID)
			}
			if recs[0].Name != tt.want.Name {
				t.Errorf("SetRecords() Name = %s, want %s", recs[0].Name, tt.want.Name)
			}
			if recs[0].Type != tt.want.Type {
				t.Errorf("SetRecords() Type = %s, want %s", recs[0].Type, tt.want.Type)
			}
			if recs[0].Value != tt.want.Value {
				t.Errorf("SetRecords() Value = %s, want %s", recs[0].Value, tt.want.Value)
			}
			if tt.want.TTL == 0 {
				tt.want.TTL = defaultTTL
			}
			if recs[0].TTL != tt.want.TTL {
				t.Errorf("SetRecords() TTL = %d, want %d", recs[0].TTL, tt.want.TTL)
			}
			if _, err := p.DeleteRecords(ctx, zone, recs); err != nil {
				t.Errorf("DeleteRecords() error = %v", err)
			}
		})
	}
}
