module github.com/libdns/cloudflare/libdnstest

go 1.18

require (
	github.com/libdns/cloudflare v1.1.0
	github.com/libdns/libdns v1.1.0
)

replace (
	github.com/libdns/cloudflare => ../
	github.com/libdns/libdns => github.com/libdns/libdns v1.2.0-alpha.1.0.20250913035451-da352cac42d0
)
