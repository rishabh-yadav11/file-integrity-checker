package model

import "testing"

func TestParseAlgorithm(t *testing.T) {
	t.Parallel()
	tests := []struct {
		in      string
		want    Algorithm
		wantErr bool
	}{
		{"", AlgoSHA256, false}, // default
		{"sha256", AlgoSHA256, false},
		{"sha512", AlgoSHA512, false},
		{"blake2b", AlgoBLAKE2b, false},
		{"md5", "", true},
		{"SHA256", "", true},
		{"sha1", "", true},
	}
	for _, tt := range tests {
		tt := tt
		t.Run("algo="+tt.in, func(t *testing.T) {
			t.Parallel()
			got, err := ParseAlgorithm(tt.in)
			if (err != nil) != tt.wantErr {
				t.Fatalf("ParseAlgorithm(%q) error = %v, wantErr %v", tt.in, err, tt.wantErr)
			}
			if got != tt.want {
				t.Fatalf("ParseAlgorithm(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}
