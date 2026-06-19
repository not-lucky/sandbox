package proxy

import (
	"reflect"
	"testing"
)

func TestParsePortMappings(t *testing.T) {
	tests := []struct {
		input   string
		want    []PortMapping
		wantErr bool
	}{
		{
			input: "",
			want:  nil,
		},
		{
			input: "38085",
			want:  []PortMapping{{HostPort: 38085, NSPort: 38085}},
		},
		{
			input: "8080:80",
			want:  []PortMapping{{HostPort: 8080, NSPort: 80}},
		},
		{
			input: "8080:80, 38085",
			want:  []PortMapping{{HostPort: 8080, NSPort: 80}, {HostPort: 38085, NSPort: 38085}},
		},
		{
			input:   "invalid",
			wantErr: true,
		},
		{
			input:   "8080:80:80",
			wantErr: true,
		},
		{
			input:   "abc:80",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		got, err := ParsePortMappings(tt.input)
		if (err != nil) != tt.wantErr {
			t.Errorf("ParsePortMappings(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
			continue
		}
		if !tt.wantErr && !reflect.DeepEqual(got, tt.want) {
			t.Errorf("ParsePortMappings(%q) = %v, want %v", tt.input, got, tt.want)
		}
	}
}
