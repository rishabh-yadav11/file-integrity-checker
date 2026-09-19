package baseline

import "time"

// parseTime parses the fixed created_at format written by Save.
func parseTime(s string) (time.Time, error) {
	return time.Parse("2006-01-02T15:04:05.000000000Z07:00", s)
}
