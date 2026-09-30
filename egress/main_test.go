// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import "testing"

func TestDestKey(t *testing.T) {
	for _, tc := range []struct {
		authority, defaultPort, want string
	}{
		{"example.com:443", "", "example.com:443"},
		{"Example.COM:443", "", "example.com:443"},
		{"example.com", "80", "example.com:80"},
		{"example.com:0443", "", "example.com:443"},
		{"[::1]:8080", "", "[::1]:8080"},
		{"[::1]", "80", "[::1]:80"},
		{"10.0.0.1:9878", "", "10.0.0.1:9878"},
	} {
		got, err := destKey(tc.authority, tc.defaultPort)
		if err != nil || got != tc.want {
			t.Errorf("destKey(%q, %q) = %q, %v; want %q", tc.authority, tc.defaultPort, got, err, tc.want)
		}
	}
}

func TestDestKeyRejects(t *testing.T) {
	for _, tc := range []struct{ authority, defaultPort string }{
		{"example.com", ""},
		{"example.com:", "80"},
		{"example.com:0", ""},
		{"example.com:99999", ""},
		{"example.com:+443", ""},
		{"user@example.com:80", ""},
		{":80", ""},
		{"a:b:c", "80"},
	} {
		if got, err := destKey(tc.authority, tc.defaultPort); err == nil {
			t.Errorf("destKey(%q, %q) = %q; want error", tc.authority, tc.defaultPort, got)
		}
	}
}
