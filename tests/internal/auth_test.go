package auth

import (
	"errors"
	"net/http"
	"testing"

	"github.com/bootdotdev/learn-cicd-starter/internal/auth"
)

func TestGetAPIKey(t *testing.T) {
	tests := []struct {
		name    string
		headers http.Header
		wantKey string
		wantErr error
	}{
		{
			name:    "no authorization header",
			headers: http.Header{},
			wantErr: auth.ErrNoAuthHeaderIncluded,
		},
		{
			name: "empty authorization header",
			headers: http.Header{
				"Authorization": []string{""},
			},
			wantErr: auth.ErrNoAuthHeaderIncluded,
		},
		{
			name: "malformed header with no ApiKey prefix",
			headers: http.Header{
				"Authorization": []string{"Bearer sometoken"},
			},
			wantErr: errors.New("malformed authorization header"),
		},
		{
			name: "malformed header missing token",
			headers: http.Header{
				"Authorization": []string{"ApiKey"},
			},
			wantErr: errors.New("malformed authorization header"),
		},
		{
			name: "valid ApiKey header",
			headers: http.Header{
				"Authorization": []string{"ApiKey my-secret-key"},
			},
			wantKey: "my-secret-key",
			wantErr: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotKey, gotErr := auth.GetAPIKey(tt.headers)

			if tt.wantErr != nil {
				if gotErr == nil || gotErr.Error() != tt.wantErr.Error() {
					t.Errorf("expected error %v, got %v", tt.wantErr, gotErr)
				}
			} else if gotKey != tt.wantKey {
				t.Errorf("expected key %q, got %q", tt.wantKey, gotKey)
			}
		})
	}
}
