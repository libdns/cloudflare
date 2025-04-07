package cloudflare

import (
	"encoding/json"
	"strings"
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
	ID         string    `json:"id,omitempty"`
	Type       string    `json:"type,omitempty"`
	Name       string    `json:"name,omitempty"`
	Content    string    `json:"content,omitempty"`
	Proxiable  bool      `json:"proxiable,omitempty"`
	Proxied    bool      `json:"proxied,omitempty"`
	TTL        int       `json:"ttl,omitempty"` // seconds
	Locked     bool      `json:"locked,omitempty"`
	ZoneID     string    `json:"zone_id,omitempty"`
	ZoneName   string    `json:"zone_name,omitempty"`
	CreatedOn  time.Time `json:"created_on,omitempty"`
	ModifiedOn time.Time `json:"modified_on,omitempty"`
	Data       struct {
		// LOC
		LatDegrees    int    `json:"lat_degrees,omitempty"`
		LatMinutes    int    `json:"lat_minutes,omitempty"`
		LatSeconds    int    `json:"lat_seconds,omitempty"`
		LatDirection  string `json:"lat_direction,omitempty"`
		LongDegrees   int    `json:"long_degrees,omitempty"`
		LongMinutes   int    `json:"long_minutes,omitempty"`
		LongSeconds   int    `json:"long_seconds,omitempty"`
		LongDirection string `json:"long_direction,omitempty"`
		Altitude      int    `json:"altitude,omitempty"`
		Size          int    `json:"size,omitempty"`
		PrecisionHorz int    `json:"precision_horz,omitempty"`
		PrecisionVert int    `json:"precision_vert,omitempty"`

		// SRV, HTTPS
		Service  string `json:"service,omitempty"`
		Proto    string `json:"proto,omitempty"`
		Name     string `json:"name,omitempty"`
		Priority uint16 `json:"priority,omitempty"`
		Weight   uint16 `json:"weight,omitempty"`
		Port     uint16 `json:"port,omitempty"`
		Target   string `json:"target,omitempty"`
		Value    string `json:"value,omitempty"`

		// DNSKEY
		Flags     int `json:"flags,omitempty"`
		Protocol  int `json:"protocol,omitempty"`
		Algorithm int `json:"algorithm,omitempty"`

		// DS
		KeyTag     int `json:"key_tag,omitempty"`
		DigestType int `json:"digest_type,omitempty"`

		// TLSA
		Usage        int `json:"usage,omitempty"`
		Selector     int `json:"selector,omitempty"`
		MatchingType int `json:"matching_type,omitempty"`

		// URI
		Content string `json:"content,omitempty"`
	} `json:"data,omitempty"`
	Meta *struct {
		AutoAdded bool   `json:"auto_added,omitempty"`
		Source    string `json:"source,omitempty"`
	} `json:"meta,omitempty"`
}

func (r cfDNSRecord) libdnsRecord(zone string) (libdns.Record, error) {
	return libdns.RR{
		Name: libdns.RelativeName(r.Name, zone),
		TTL:  time.Duration(r.TTL) * time.Second,
		Type: r.Type,
		Data: r.Content,
	}.Parse()
}

func cloudflareRecord(r libdns.Record) (cfDNSRecord, error) {
	// Super annoyingly, the Cloudflare API says that a "Content"
	// field can contain the record data as a string, and that the
	// individual component fields are optional (this would be
	// ideal so we don't have to parse every single record type
	// into a separate struct, we can just submit the Content
	// string like what the RR struct has for us); yet when I try
	// to submit records using the Content field, I get errors
	// saying that the individual data components are required,
	// despite the docs saying they're optional.
	// So, instead of a 5-line function, we have a much bigger
	// more complicated and error prone function here.
	// And of course there's no real good venue to file a bug report:
	// https://community.cloudflare.com/t/creating-srv-record-with-content-string-instead-of-individual-component-fields/781178?u=mholt
	rr := r.RR()
	cfRec := cfDNSRecord{
		// ID:   r.ID,
		Name:    rr.Name,
		Type:    rr.Type,
		TTL:     int(rr.TTL.Seconds()),
		Content: rr.Data,
	}
	switch rec := r.(type) {
	case libdns.SRV:
		cfRec.Data.Service = "_" + rec.Service
		cfRec.Data.Priority = rec.Priority
		cfRec.Data.Weight = rec.Weight
		cfRec.Data.Proto = "_" + rec.Transport
		cfRec.Data.Name = rec.Name
		cfRec.Data.Port = rec.Port
		cfRec.Data.Target = rec.Target
	case libdns.ServiceBinding:
		cfRec.Name = rec.Name
		cfRec.Data.Priority = rec.Priority
		cfRec.Data.Target = rec.Target
		cfRec.Data.Value = rec.Params.String()
	}
	if rr.Type == "CNAME" && strings.HasSuffix(cfRec.Content, ".cfargotunnel.com") {
		cfRec.Proxied = true
	}
	return cfRec, nil
}

// All API responses have this structure.
type cfResponse struct {
	Result  json.RawMessage `json:"result,omitempty"`
	Success bool            `json:"success"`
	Errors  []struct {
		Code       int    `json:"code"`
		Message    string `json:"message"`
		ErrorChain []struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"error_chain,omitempty"`
	} `json:"errors,omitempty"`
	Messages   []any         `json:"messages,omitempty"`
	ResultInfo *cfResultInfo `json:"result_info,omitempty"`
}

type cfResultInfo struct {
	Page       int `json:"page"`
	PerPage    int `json:"per_page"`
	Count      int `json:"count"`
	TotalCount int `json:"total_count"`
}
