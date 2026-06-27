package cloudflare

import (
	"fmt"
	"strings"
)

// Cloudflare stores and returns TXT record content in RFC 1035 zone-file
// presentation: one or more "character-strings" of at most 255 octets each,
// each wrapped in double quotes and separated by spaces. Within a quoted
// string, '"' and '\' are backslash-escaped and any other non-printable or
// high-bit octet is written as a three-digit decimal escape (\DDD). libdns, by
// contrast, models the whole TXT value as a single arbitrary-length,
// arbitrary-byte string (see libdns.TXT.Text). encodeTXT and decodeTXT
// translate between the two.
//
// Cloudflare accepts and faithfully round-trips every octet 0x00-0xFF through
// the \DDD form, up to its 4096 wire-format-byte limit. Some bytes (embedded
// NUL especially) may not survive every DNS resolver, but that is a transport
// concern, not a storage one, so the codec does not police byte values.

const txtMaxChunk = 255

// encodeTXT converts a raw TXT value into Cloudflare's content field.
func encodeTXT(text string) string {
	// An empty value encodes to "" (a single empty character-string).
	// Cloudflare rejects that with a clear error, which we surface rather than
	// silently swallow.
	if len(text) == 0 {
		return `""`
	}

	var sb strings.Builder
	sep := ""
	for len(text) > 0 {
		sb.WriteString(sep)
		sep = " "

		n := txtMaxChunk
		if n > len(text) {
			n = len(text)
		}
		chunk := text[:n]
		text = text[n:]

		sb.WriteByte('"')
		for j := 0; j < len(chunk); j++ {
			b := chunk[j]
			switch {
			case b == '"':
				sb.WriteString(`\"`)
			case b == '\\':
				sb.WriteString(`\\`)
			case b >= 0x20 && b <= 0x7E:
				sb.WriteByte(b)
			default:
				fmt.Fprintf(&sb, `\%03d`, b)
			}
		}
		sb.WriteByte('"')
	}
	return sb.String()
}

// decodeTXT converts Cloudflare's TXT content field back into the raw value.
//
// Quoted content is parsed as one or more space-separated character-strings;
// the decoded octets of every segment are concatenated (libdns's "one long
// string" model). Unquoted content is returned verbatim -- Cloudflare accepts
// and returns it literally and does NOT interpret escapes in that form.
//
// An error is returned only for genuinely malformed presentation; Cloudflare's
// own output never triggers it, so the errors guard against corrupt data from
// elsewhere rather than normal operation.
func decodeTXT(content string) (string, error) {
	if !strings.HasPrefix(content, `"`) {
		return content, nil
	}

	var out []byte
	i := 0
	for i < len(content) {
		for i < len(content) && (content[i] == ' ' || content[i] == '\t') {
			i++
		}
		if i == len(content) {
			break
		}
		if content[i] != '"' {
			return "", fmt.Errorf("malformed TXT content: unexpected %q at offset %d", content[i], i)
		}
		i++

		closed := false
		for i < len(content) {
			b := content[i]
			if b == '"' {
				i++
				closed = true
				break
			}
			if b == '\\' {
				if i+1 >= len(content) {
					return "", fmt.Errorf("malformed TXT content: trailing backslash")
				}
				next := content[i+1]
				if next >= '0' && next <= '9' {
					if i+3 >= len(content) {
						return "", fmt.Errorf("malformed TXT content: incomplete decimal escape at offset %d", i)
					}
					d1, d2 := content[i+2], content[i+3]
					if d1 < '0' || d1 > '9' || d2 < '0' || d2 > '9' {
						return "", fmt.Errorf("malformed TXT content: invalid decimal escape at offset %d", i)
					}
					val := int(next-'0')*100 + int(d1-'0')*10 + int(d2-'0')
					if val > 255 {
						return "", fmt.Errorf("malformed TXT content: decimal escape %d out of range at offset %d", val, i)
					}
					out = append(out, byte(val))
					i += 4
				} else {
					// \<non-digit> represents that character literally.
					out = append(out, next)
					i += 2
				}
				continue
			}
			out = append(out, b)
			i++
		}
		if !closed {
			return "", fmt.Errorf("malformed TXT content: unterminated quoted string")
		}
	}
	return string(out), nil
}
