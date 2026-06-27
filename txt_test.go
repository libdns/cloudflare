package cloudflare

import (
	"strings"
	"testing"
)

func TestEncodeTXT(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"empty", "", `""`},
		{"ascii", "v=spf1 -all", `"v=spf1 -all"`},
		{"dquote", `a"b`, `"a\"b"`},
		{"backslash", `a\b`, `"a\\b"`},
		{"tab", "x\ty", `"x\009y"`},
		{"nul", "x\x00y", `"x\000y"`},
		{"highbit", "x\xffy", `"x\255y"`},
		{"utf8-eacute", "é", `"\195\169"`}, // é = 0xC3 0xA9
		{"semicolon-kept", "v=spf1; -all", `"v=spf1; -all"`},
		{"exactly-255", strings.Repeat("a", 255), `"` + strings.Repeat("a", 255) + `"`},
		{"256-splits", strings.Repeat("a", 256), `"` + strings.Repeat("a", 255) + `" "a"`},
		{"300-splits", strings.Repeat("a", 300), `"` + strings.Repeat("a", 255) + `" "` + strings.Repeat("a", 45) + `"`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := encodeTXT(c.in)
			if got != c.want {
				t.Fatalf("encodeTXT(%q):\n want %q\n got  %q", c.in, c.want, got)
			}
		})
	}
}

func TestDecodeTXT(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"ascii", `"hello"`, "hello"},
		{"dquote", `"a\"b"`, `a"b`},
		{"backslash", `"a\\b"`, `a\b`},
		{"decimal-A", `"x\065y"`, "xAy"},
		{"tab", `"x\009y"`, "x\ty"},
		{"utf8-eacute", `"h\195\169llo"`, "héllo"},
		{"two-segments", `"a" "b"`, "ab"},
		{"empty-quoted", `""`, ""},
		{"unquoted-literal", "hello world", "hello world"},
		{"unquoted-escape-not-interpreted", `x\065y`, `x\065y`},
		{"backslash-nondigit", `"a\zb"`, "azb"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := decodeTXT(c.in)
			if err != nil {
				t.Fatalf("decodeTXT(%q) unexpected error: %v", c.in, err)
			}
			if got != c.want {
				t.Fatalf("decodeTXT(%q):\n want %q\n got  %q", c.in, c.want, got)
			}
		})
	}
}

func TestDecodeTXTErrors(t *testing.T) {
	bad := []struct{ name, in string }{
		{"unterminated", `"abc`},
		{"trailing-backslash", `"abc\`},
		{"short-decimal", `"a\99"`}, // \99 then '"' -- not 3 digits
		{"garbage-after-segment", `"a"x`},
		{"decimal-out-of-range", `"\256"`},
		{"incomplete-decimal", `"\09`},
	}
	for _, c := range bad {
		t.Run(c.name, func(t *testing.T) {
			if _, err := decodeTXT(c.in); err == nil {
				t.Fatalf("decodeTXT(%q): expected error, got nil", c.in)
			}
		})
	}
}

func allBytes() string {
	b := make([]byte, 256)
	for i := range b {
		b[i] = byte(i)
	}
	return string(b)
}

func TestTXTRoundTrip(t *testing.T) {
	dkim := "v=DKIM1; k=rsa; p=" + strings.Repeat("MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA", 9) + "IDAQAB"
	payloads := map[string]string{
		"empty":            "",
		"ascii":            "v=spf1 include:example.com -all",
		"quote-backslash":  `has "quotes" and \back\slash`,
		"all-256-bytes":    allBytes(),
		"dkim-410":         dkim,
		"utf8":             "café ☕ 日本語",
		"nul-highbit-span": strings.Repeat("\x00\xff", 200), // 400 bytes across 255 boundary
		"len-1000":         strings.Repeat("A", 1000),
		"len-2048":         strings.Repeat("B", 2048),
	}
	for name, p := range payloads {
		t.Run(name, func(t *testing.T) {
			got, err := decodeTXT(encodeTXT(p))
			if err != nil {
				t.Fatalf("decode(encode(%s)) error: %v", name, err)
			}
			if got != p {
				t.Fatalf("round-trip mismatch for %s (len %d -> %d)", name, len(p), len(got))
			}
		})
	}
}

func TestEncodeTXTChunkCount(t *testing.T) {
	cases := []struct {
		n      int
		chunks int
	}{
		{0, 1}, {1, 1}, {255, 1}, {256, 2}, {510, 2}, {511, 3}, {1000, 4},
	}
	for _, c := range cases {
		// Payload is quote-free, so there are no escaped \" and the segment
		// count equals (number of " characters) / 2.
		got := strings.Count(encodeTXT(strings.Repeat("a", c.n)), `"`) / 2
		if got != c.chunks {
			t.Fatalf("encodeTXT(%d bytes): want %d chunks, got %d", c.n, c.chunks, got)
		}
	}
}

// countTXTSegments counts the quoted character-strings in encodeTXT output,
// scanning escape sequences so that an escaped quote (\") or backslash (\\) is
// not mistaken for a structural quote, and a literal space inside a segment is
// not mistaken for a segment separator.
func countTXTSegments(content string) int {
	n := 0
	for i := 0; i < len(content); {
		if content[i] != '"' {
			i++
			continue
		}
		n++
		i++
		for i < len(content) && content[i] != '"' {
			if content[i] == '\\' {
				i += 2 // skip the escaped byte (\" , \\ , or first digit of \DDD)
			} else {
				i++
			}
		}
		i++
	}
	return n
}

// TestEncodeTXTChunkBoundaryByOctet pins that chunking is by RAW octet, not by
// escaped presentation width: a 255-octet chunk is one character-string even
// when its presentation is far longer than 255 chars, and the 256th octet
// starts a new chunk regardless of whether it escapes to 1, 2, or 4 chars.
func TestEncodeTXTChunkBoundaryByOctet(t *testing.T) {
	cases := []struct {
		name     string
		in       string
		segments int
	}{
		{"255-dquotes-1-segment", strings.Repeat(`"`, 255), 1},
		{"256-dquotes-2-segments", strings.Repeat(`"`, 256), 2},
		{"255-0xff-1-segment", strings.Repeat("\xff", 255), 1},
		{"254a-dquote-1-segment", strings.Repeat("a", 254) + `"`, 1},
		{"255a-dquote-2-segments", strings.Repeat("a", 255) + `"`, 2},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			enc := encodeTXT(c.in)
			if got := countTXTSegments(enc); got != c.segments {
				t.Fatalf("segment count: want %d, got %d (presentation len %d)", c.segments, got, len(enc))
			}
			dec, err := decodeTXT(enc)
			if err != nil {
				t.Fatalf("decode: %v", err)
			}
			if dec != c.in {
				t.Fatalf("round-trip mismatch (in %d octets -> out %d)", len(c.in), len(dec))
			}
		})
	}
}
