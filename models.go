package cloudflare

import (
	"encoding/json"
	"time"

	"github.com/libdns/libdns"
)

type cfZone struct {
	ID                  string    `json:"id"`
	Name                string    `json:"name"`
	DevelopmentMode     int       `json:"development_mode"`
	OriginalNameServers []string  `json:"original_name_servers"`
	OriginalRegistrar   string    `json:"original_registrar"`
	OriginalDnshost     string    `json:"original_dnshost"`
	CreatedOn           time.Time `json:"created_on"`
	ModifiedOn          time.Time `json:"modified_on"`
	ActivatedOn         time.Time `json:"activated_on"`
	Account             struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	} `json:"account"`
	Permissions []string `json:"permissions"`
	Plan        struct {
		ID           string `json:"id"`
		Name         string `json:"name"`
		Price        int    `json:"price"`
		Currency     string `json:"currency"`
		Frequency    string `json:"frequency"`
		LegacyID     string `json:"legacy_id"`
		IsSubscribed bool   `json:"is_subscribed"`
		CanSubscribe bool   `json:"can_subscribe"`
	} `json:"plan"`
	PlanPending struct {
		ID           string `json:"id"`
		Name         string `json:"name"`
		Price        int    `json:"price"`
		Currency     string `json:"currency"`
		Frequency    string `json:"frequency"`
		LegacyID     string `json:"legacy_id"`
		IsSubscribed bool   `json:"is_subscribed"`
		CanSubscribe bool   `json:"can_subscribe"`
	} `json:"plan_pending"`
	Status      string   `json:"status"`
	Paused      bool     `json:"paused"`
	Type        string   `json:"type"`
	NameServers []string `json:"name_servers"`
}

type cfDNSRecord struct {
	ID         string    `json:"id"`
	Type       string    `json:"type"`
	Name       string    `json:"name"`
	Content    string    `json:"content"`
	Proxiable  bool      `json:"proxiable"`
	Proxied    bool      `json:"proxied"`
	TTL        int       `json:"ttl"` // seconds
	Locked     bool      `json:"locked"`
	ZoneID     string    `json:"zone_id"`
	ZoneName   string    `json:"zone_name"`
	CreatedOn  time.Time `json:"created_on"`
	ModifiedOn time.Time `json:"modified_on"`
	Data       struct {
		// LOC
		LatDegrees    int    `json:"lat_degrees"`
		LatMinutes    int    `json:"lat_minutes"`
		LatSeconds    int    `json:"lat_seconds"`
		LatDirection  string `json:"lat_direction"`
		LongDegrees   int    `json:"long_degrees"`
		LongMinutes   int    `json:"long_minutes"`
		LongSeconds   int    `json:"long_seconds"`
		LongDirection string `json:"long_direction"`
		Altitude      int    `json:"altitude"`
		Size          int    `json:"size"`
		PrecisionHorz int    `json:"precision_horz"`
		PrecisionVert int    `json:"precision_vert"`

		// SRV
		Service  string `json:"service"`
		Proto    string `json:"proto"`
		Name     string `json:"name"`
		Priority int    `json:"priority"`
		Weight   int    `json:"weight"`
		Port     int    `json:"port"`
		Target   string `json:"target"`

		// DNSKEY
		Flags     int `json:"flags"`
		Protocol  int `json:"protocol"`
		Algorithm int `json:"algorithm"`

		// DS
		KeyTag     int `json:"key_tag"`
		DigestType int `json:"digest_type"`

		// TLSA
		Usage        int `json:"usage"`
		Selector     int `json:"selector"`
		MatchingType int `json:"matching_type"`

		// URI
		Content string `json:"content"`
	} `json:"data"`
	Meta struct {
		AutoAdded bool   `json:"auto_added"`
		Source    string `json:"source"`
	} `json:"meta"`
}

func (r cfDNSRecord) libdnsRecord() libdns.Record {
	return libdns.Record{
		Type:  r.Type,
		Name:  r.Name,
		Value: r.Content,
		TTL:   time.Duration(r.TTL) * time.Second,
		ID:    r.ID,
	}
}

func cloudflareRecord(r libdns.Record) cfDNSRecord {
	return cfDNSRecord{
		ID:      r.ID,
		Type:    r.Type,
		Name:    r.Name,
		Content: r.Value,
		TTL:     int(r.TTL.Seconds()),
	}
}

// All API responses have this structure.
type cfResponse struct {
	Result  json.RawMessage `json:"result,omitempty"`
	Success bool            `json:"success"`
	Errors  []struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	} `json:"errors,omitempty"`
	Messages   []interface{} `json:"messages,omitempty"`
	ResultInfo *cfResultInfo `json:"result_info,omitempty"`
}

type cfResultInfo struct {
	Page       int `json:"page"`
	PerPage    int `json:"per_page"`
	Count      int `json:"count"`
	TotalCount int `json:"total_count"`
}
