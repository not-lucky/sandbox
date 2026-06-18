package identity

import (
	"testing"
)

func TestSanitize(t *testing.T) {
	cases := []struct{ in, out string }{
		{"foo-bar", "foo-bar"},
		{"foo/bar", "foobar"},
		{"a!b@c#d$e%f^g&h*i(j)", "abcdefghij"},
		{"test_123", "test_123"},
	}
	for _, c := range cases {
		if got := Sanitize(c.in); got != c.out {
			t.Errorf("Sanitize(%q) == %q, want %q", c.in, got, c.out)
		}
	}
}

func TestHash(t *testing.T) {
	// md5("test") = 098f6bcd4621d373cade4e832627b4f6
	if got := Hash("test"); got != "098f6b" {
		t.Errorf("Hash(\"test\") == %q, want \"098f6b\"", got)
	}
}
