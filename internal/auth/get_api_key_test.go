package auth

import (
	"errors"
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	tests := []struct {
		name    string
		headers http.Header
		want    string
		wantErr error
		anyErr  bool // expect an error that is not ErrNoAuthHeaderIncluded
	}{
		{
			name:    "valid ApiKey header",
			headers: http.Header{"Authorization": []string{"ApiKey secret123"}},
			want:    "secret123",
		},
		{
			name:    "valid header with extra parts returns first token",
			headers: http.Header{"Authorization": []string{"ApiKey secret123 extra"}},
			want:    "secret123",
		},
		{
			name:    "no headers at all",
			headers: http.Header{},
			wantErr: ErrNoAuthHeaderIncluded,
		},
		{
			name:    "nil headers",
			headers: nil,
			wantErr: ErrNoAuthHeaderIncluded,
		},
		{
			name:    "empty authorization value",
			headers: http.Header{"Authorization": []string{""}},
			wantErr: ErrNoAuthHeaderIncluded,
		},
		{
			name:    "wrong scheme Bearer",
			headers: http.Header{"Authorization": []string{"Bearer token"}},
			anyErr:  true,
		},
		{
			name:    "scheme is case sensitive",
			headers: http.Header{"Authorization": []string{"apikey secret123"}},
			anyErr:  true,
		},
		{
			name:    "scheme only, no key",
			headers: http.Header{"Authorization": []string{"ApiKey"}},
			anyErr:  true,
		},
		{
			name:    "key only, no scheme",
			headers: http.Header{"Authorization": []string{"secret123"}},
			anyErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := GetAPIKey(tt.headers)

			switch {
			case tt.wantErr != nil:
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("error = %v, want %v", err, tt.wantErr)
				}
			case tt.anyErr:
				if err == nil {
					t.Fatalf("expected error, got key %q", got)
				}
				if errors.Is(err, ErrNoAuthHeaderIncluded) {
					t.Fatalf("expected malformed-header error, got %v", err)
				}
			default:
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
			}

			if got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}
