package baseline

import (
	"bytes"
	"time"
)

func bytesReader(b []byte) *bytes.Reader { return bytes.NewReader(rawBytes(b)) }

// rawBytes avoids an extra copy; identity for byte slices.
func rawBytes(b []byte) []byte { return b }

func parseTime(s string) (time.Time, error) {
	return time.Parse("2006-01-02T15:04:05.000000000Z07:00", s)
}
