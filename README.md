Cloudflare for `libdns`
=======================

[![godoc reference](https://img.shields.io/badge/godoc-reference-blue.svg)](https://pkg.go.dev/github.com/libdns/cloudflare)

This package implements the [libdns interfaces](https://github.com/libdns/libdns) for [Cloudflare](https://www.cloudflare.com).

It supports API token authentication. You will need to create a token with the following permissions:

- Zone / Zone / Read
- Zone / DNS / Edit

The first permission is needed to get the zone ID, and the second permission is obviously necessary to edit the DNS records. If you're only using the `GetRecords()` method, you can change the second permission to Read to guarantee no changes will be made.
