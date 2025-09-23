# Provider-Specific Tests for Cloudflare

This directory contains provider-specific tests for the Cloudflare libdns provider using the official [libdnstest package](https://github.com/libdns/libdns/tree/master/libdnstest). These tests verify the provider implementation against the real Cloudflare API, ensuring all libdns interface methods work correctly with actual DNS operations.

## How To Run

1. **Get API Token and setup zone**: See main README for token setup instructions. Test will use single or dual token depending on env variables. Setup some test Cloudflare zone.

2. **Set Environment Variables**:
```bash
export CLOUDFLARE_API_TOKEN="your-token-here"
export CLOUDFLARE_TEST_ZONE="example.org."  # Include trailing dot
```

Or copy `.env.example` to `.env` and fill in values.

3. **Run Tests**

```bash
set -a && source .env && set +a && go test -v
```

## What Gets Tested

- ListZones, GetRecords, AppendRecords, SetRecords, DeleteRecords
- Complete record lifecycle (create → update → delete)
- Various DNS record types

**Warning**: Tests create/delete real DNS records prefixed with "test-". Use a dedicated test zone or ensure you have backups.
