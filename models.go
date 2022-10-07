package cloudflare

import (
	"encoding/json"
	"fmt"
	"strconv"
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
	Priority   int       `json:"priority,omitempty"`
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

		// SRV
		Service  string `json:"service,omitempty"`
		Proto    string `json:"proto,omitempty"`
		Name     string `json:"name,omitempty"`
		Priority uint   `json:"priority,omitempty"`
		Weight   uint   `json:"weight,omitempty"`
		Port     uint   `json:"port,omitempty"`
		Target   string `json:"target,omitempty"`

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

func (r cfDNSRecord) libdnsRecord(zone string) libdns.Record {
	switch r.Type {
	case "SRV":
		srv := libdns.SRV{
			Service:  strings.TrimPrefix(r.Data.Service, "_"),
			Proto:    strings.TrimPrefix(r.Data.Proto, "_"),
			Name:     r.Data.Name,
			Priority: r.Data.Priority,
			Weight:   r.Data.Weight,
			Port:     r.Data.Port,
			Target:   r.Data.Target,
		}
		return libdns.Record{
			ID:       r.ID,
			Type:     r.Type,
			Name:     libdns.RelativeName(r.Name, zone),
			Value:    fmt.Sprintf("%d %d %d %s", srv.Priority, srv.Weight, srv.Port, libdns.RelativeName(srv.Target, zone)),
			TTL:      time.Duration(r.TTL) * time.Second,
			Priority: srv.Priority,
			Weight:   srv.Weight,
		}
	case "MX":
		r.Content = fmt.Sprintf("%d %s", r.Priority, r.Content)
		fallthrough
	default:
		return libdns.Record{
			Type:  r.Type,
			Name:  libdns.RelativeName(r.Name, zone),
			Value: libdns.RelativeName(r.Content, zone),
			TTL:   time.Duration(r.TTL) * time.Second,
			ID:    r.ID,
		}

	}
}

func cloudflareRecord(r libdns.Record) (cfDNSRecord, error) {
	rec := cfDNSRecord{
		ID:   r.ID,
		Type: r.Type,
		TTL:  int(r.TTL.Seconds()),
	}
	if r.Name == "" {
		rec.Name = "@"
	} else {
		rec.Name = r.Name
	}
	switch r.Type {
	case "SRV":
		nameParts := strings.Split(r.Name, ".")
		if len(nameParts) == 2 {
			nameParts = append(nameParts, "@")
		} else if len(nameParts) < 3 {
			return cfDNSRecord{}, fmt.Errorf("invalid SRV record name: %s, expected _<service>._<proto>", r.Name)
		}
		valueParts := strings.Fields(r.Value)
		if len(valueParts) != 4 {
			return cfDNSRecord{}, fmt.Errorf("invalid SRV record value: %s, expected <priority> <weight> <port> <target>", r.Value)
		}
		priority, err := strconv.ParseUint(valueParts[0], 10, 64)
		if err != nil {
			return cfDNSRecord{}, fmt.Errorf("invalid SRV record value: priority is not a number: %s", valueParts[0])
		}
		weight, err := strconv.ParseUint(valueParts[1], 10, 64)
		if err != nil {
			return cfDNSRecord{}, fmt.Errorf("invalid SRV record value: weight is not a number: %s", valueParts[1])
		}
		port, err := strconv.Atoi(valueParts[2])
		if err != nil {
			return cfDNSRecord{}, fmt.Errorf("invalid SRV record value: target port is not a number: %s", valueParts[2])
		}
		if priority < 0 || priority > 65535 {
			return cfDNSRecord{}, fmt.Errorf("invalid SRV record value: priority is out of range 0-65535: %d", priority)
		}
		rec.Data.Service = nameParts[0]
		rec.Data.Priority = uint(priority)
		rec.Data.Weight = uint(weight)
		rec.Data.Proto = nameParts[1]
		rec.Data.Name = strings.Join(nameParts[2:], ".")
		rec.Data.Port = uint(port)
		rec.Data.Target = strings.Join(valueParts[3:], ".")
	case "MX":
		valueParts := strings.Fields(r.Value)
		if r.Priority == 0 && len(valueParts) != 2 {
			return cfDNSRecord{}, fmt.Errorf("invalid MX record value: %s, expected <priority> <target> or Priority to be set", r.Value)
		}
		if len(valueParts) == 2 {
			priority, err := strconv.ParseUint(valueParts[0], 10, 64)
			if err != nil {
				return cfDNSRecord{}, fmt.Errorf("invalid MX record value: priority is not a number: %s", valueParts[0])
			}
			r.Priority = uint(priority)
		}
		if len(valueParts) == 2 {
			rec.Content = valueParts[1]
		} else {
			rec.Content = r.Value
		}
		rec.Priority = int(r.Priority)
	default:
		rec.Content = r.Value
	}
	return rec, nil
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
