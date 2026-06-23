package cli

import (
	"reflect"
	"strings"
	"testing"

	"cloakid/internal/proxy"
)

func TestResolveForwardMappings(t *testing.T) {
	tests := []struct {
		name       string
		forward    string
		forwardAll bool
		want       []proxy.PortMapping
		wantErr    bool
		errSubstr  string
	}{
		{
			name:    "empty / no auto",
			want:    nil,
		},
		{
			name:    "single port",
			forward: "38085",
			want:    []proxy.PortMapping{{HostPort: 38085, NSPort: 38085}},
		},
		{
			name:    "host to ns mapping",
			forward: "8080:80",
			want:    []proxy.PortMapping{{HostPort: 8080, NSPort: 80}},
		},
		{
			name:    "auto only",
			forwardAll: true,
			want:    nil,
		},
		{
			name:       "both flags set is rejected",
			forward:    "38085",
			forwardAll: true,
			wantErr:    true,
			errSubstr:  "mutually exclusive",
		},
		{
			name:      "invalid mapping propagates parse error",
			forward:   "abc",
			wantErr:   true,
			errSubstr: "invalid port",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := resolveForwardMappings(tt.forward, tt.forwardAll)
			if (err != nil) != tt.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr {
				if tt.errSubstr != "" && !strings.Contains(err.Error(), tt.errSubstr) {
					t.Fatalf("err = %q, want substring %q", err.Error(), tt.errSubstr)
				}
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("got %v, want %v", got, tt.want)
			}
		})
	}
}
