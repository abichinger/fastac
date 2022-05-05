// Copyright 2017 The casbin Authors. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package util

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func testGlobMatch(t *testing.T, key1 string, key2 string, res bool) {
	t.Helper()
	myRes, err := GlobMatch(key1, key2)
	if err != nil {
		panic(err)
	}
	t.Logf("%s < %s: %t", key1, key2, myRes)

	if myRes != res {
		t.Errorf("%s < %s: %t, supposed to be %t", key1, key2, !res, res)
	}
}

func testRegexMatch(t *testing.T, key1 string, key2 string, res bool) {
	t.Helper()
	myRes := RegexMatch(key1, key2)
	t.Logf("%s < %s: %t", key1, key2, myRes)

	if myRes != res {
		t.Errorf("%s < %s: %t, supposed to be %t", key1, key2, !res, res)
	}
}

func TestRegexMatch(t *testing.T) {
	testRegexMatch(t, "/topic/create", "/topic/create", true)
	testRegexMatch(t, "/topic/create/123", "/topic/create", true)
	testRegexMatch(t, "/topic/delete", "/topic/create", false)
	testRegexMatch(t, "/topic/edit", "/topic/edit/[0-9]+", false)
	testRegexMatch(t, "/topic/edit/123", "/topic/edit/[0-9]+", true)
	testRegexMatch(t, "/topic/edit/abc", "/topic/edit/[0-9]+", false)
	testRegexMatch(t, "/foo/delete/123", "/topic/delete/[0-9]+", false)
	testRegexMatch(t, "/topic/delete/0", "/topic/delete/[0-9]+", true)
	testRegexMatch(t, "/topic/edit/123s", "/topic/delete/[0-9]+", false)
}

func testIPMatch(t *testing.T, ip1 string, ip2 string, res bool) {
	t.Helper()
	myRes := IPMatch(ip1, ip2)
	t.Logf("%s < %s: %t", ip1, ip2, myRes)

	if myRes != res {
		t.Errorf("%s < %s: %t, supposed to be %t", ip1, ip2, !res, res)
	}
}

func TestIPMatch(t *testing.T) {
	testIPMatch(t, "192.168.2.123", "192.168.2.0/24", true)
	testIPMatch(t, "192.168.2.123", "192.168.3.0/24", false)
	testIPMatch(t, "192.168.2.123", "192.168.2.0/16", true)
	testIPMatch(t, "192.168.2.123", "192.168.2.123", true)
	testIPMatch(t, "192.168.2.123", "192.168.2.123/32", true)
	testIPMatch(t, "10.0.0.11", "10.0.0.0/8", true)
	testIPMatch(t, "11.0.0.123", "10.0.0.0/8", false)
}

func testRegexMatchFunc(t *testing.T, res bool, err string, args ...interface{}) {
	t.Helper()
	myRes, myErr := RegexMatchFunc(args...)
	myErrStr := ""

	if myErr != nil {
		myErrStr = myErr.Error()
	}

	if myRes != res || err != myErrStr {
		t.Errorf("%v returns %v %v, supposed to be %v %v", args, myRes, myErr, res, err)
	}
}

func testIPMatchFunc(t *testing.T, res bool, err string, args ...interface{}) {
	t.Helper()
	myRes, myErr := IPMatchFunc(args...)
	myErrStr := ""

	if myErr != nil {
		myErrStr = myErr.Error()
	}

	if myRes != res || err != myErrStr {
		t.Errorf("%v returns %v %v, supposed to be %v %v", args, myRes, myErr, res, err)
	}
}

func testPathMatch(t *testing.T, expected bool, path string, pattern string) {
	t.Helper()
	res := PathMatch(path, pattern)
	assert.Equalf(t, expected, res, "path: %s, pattern: %s", path, pattern)
}

func TestRegexMatchFunc(t *testing.T) {
	testRegexMatchFunc(t, false, "RegexMatch: Expected 2 arguments, but got 1", "/topic/create")
	testRegexMatchFunc(t, false, "RegexMatch: Expected 2 arguments, but got 3", "/topic/create/123", "/topic/create", "/topic/update")
	testRegexMatchFunc(t, false, "RegexMatch: Argument must be a string", "/topic/create", false)
	testRegexMatchFunc(t, true, "", "/topic/create/123", "/topic/create")
}

func TestIPMatchFunc(t *testing.T) {
	testIPMatchFunc(t, false, "IPMatch: Expected 2 arguments, but got 1", "192.168.2.123")
	testIPMatchFunc(t, false, "IPMatch: Argument must be a string", "192.168.2.123", 128)
	testIPMatchFunc(t, true, "", "192.168.2.123", "192.168.2.0/24")
}

func TestGlobMatch(t *testing.T) {
	testGlobMatch(t, "/foo", "/foo", true)
	testGlobMatch(t, "/foo", "/foo*", true)
	testGlobMatch(t, "/foo", "/foo/*", false)
	testGlobMatch(t, "/foo/bar", "/foo", false)
	testGlobMatch(t, "/foo/bar", "/foo*", false)
	testGlobMatch(t, "/foo/bar", "/foo/*", true)
	testGlobMatch(t, "/foobar", "/foo", false)
	testGlobMatch(t, "/foobar", "/foo*", true)
	testGlobMatch(t, "/foobar", "/foo/*", false)

	testGlobMatch(t, "/foo", "*/foo", true)
	testGlobMatch(t, "/foo", "*/foo*", true)
	testGlobMatch(t, "/foo", "*/foo/*", false)
	testGlobMatch(t, "/foo/bar", "*/foo", false)
	testGlobMatch(t, "/foo/bar", "*/foo*", false)
	testGlobMatch(t, "/foo/bar", "*/foo/*", true)
	testGlobMatch(t, "/foobar", "*/foo", false)
	testGlobMatch(t, "/foobar", "*/foo*", true)
	testGlobMatch(t, "/foobar", "*/foo/*", false)

	testGlobMatch(t, "/prefix/foo", "*/foo", false)
	testGlobMatch(t, "/prefix/foo", "*/foo*", false)
	testGlobMatch(t, "/prefix/foo", "*/foo/*", false)
	testGlobMatch(t, "/prefix/foo/bar", "*/foo", false)
	testGlobMatch(t, "/prefix/foo/bar", "*/foo*", false)
	testGlobMatch(t, "/prefix/foo/bar", "*/foo/*", false)
	testGlobMatch(t, "/prefix/foobar", "*/foo", false)
	testGlobMatch(t, "/prefix/foobar", "*/foo*", false)
	testGlobMatch(t, "/prefix/foobar", "*/foo/*", false)

	testGlobMatch(t, "/prefix/subprefix/foo", "*/foo", false)
	testGlobMatch(t, "/prefix/subprefix/foo", "*/foo*", false)
	testGlobMatch(t, "/prefix/subprefix/foo", "*/foo/*", false)
	testGlobMatch(t, "/prefix/subprefix/foo/bar", "*/foo", false)
	testGlobMatch(t, "/prefix/subprefix/foo/bar", "*/foo*", false)
	testGlobMatch(t, "/prefix/subprefix/foo/bar", "*/foo/*", false)
	testGlobMatch(t, "/prefix/subprefix/foobar", "*/foo", false)
	testGlobMatch(t, "/prefix/subprefix/foobar", "*/foo*", false)
	testGlobMatch(t, "/prefix/subprefix/foobar", "*/foo/*", false)
}

func TestPathMatch(t *testing.T) {
	testPathMatch(t, false, "/", "")
	testPathMatch(t, false, "", "/")
	testPathMatch(t, true, "/", "/")

	testPathMatch(t, true, "/api/v1", "/api/v1")
	testPathMatch(t, false, "/api/v1/user", "/api/v1")
	testPathMatch(t, false, "/api/v1", "/api/v1/user")

	testPathMatch(t, true, "/api", "/:")
	testPathMatch(t, false, "/api", "/api/:")
	testPathMatch(t, true, "/api/v1", "/api/:")
	testPathMatch(t, true, "/api/v1", "/api/:v")
	testPathMatch(t, false, "/api/v1/user/5", "/api/:v")
	testPathMatch(t, true, "/api/v1/user/id", "/api/:v/user/:id")

	testPathMatch(t, true, "", "*")
	testPathMatch(t, false, "", "/*")
	testPathMatch(t, true, "/api", "*")
	testPathMatch(t, true, "/api", "/*")
	testPathMatch(t, true, "/api/v1", "/*")
	testPathMatch(t, false, "/app", "/app/*")

	testPathMatch(t, false, "/api/v1", "/api/:v/*")
	testPathMatch(t, true, "/api/v1/user", "/api/:v/*")
	testPathMatch(t, true, "/api/v1/user/5", "/api/:v/*")

	testPathMatch(t, false, "/api/v1/user/5", "/api/:v/*/profile")
	testPathMatch(t, true, "/api/v1/group/2/profile", "/api/:v/*/profile")
	testPathMatch(t, true, "/api/v1/user/5/profile", "/api/:v/*/profile")
	testPathMatch(t, false, "/api/v1/user/5/profile/name", "/api/:v/*/profile")
}

func TestIsPathPattern(t *testing.T) {

	tests := []struct {
		path     string
		expected bool
	}{
		{"", false},
		{"*", true},
		{"/api/*", true},
		{"/api/*/user", true},
		{"/api/v1", false},
		{"/api/:v", true},
		{"/api/:v/user", true},
	}

	for _, test := range tests {
		res := IsPathPattern(test.path)
		assert.Equal(t, test.expected, res, test.path)
	}

}

func TestMatcher(t *testing.T) {

	m := NewMatcher(func(str string) bool { return true }, RegexMatch)

	tests := []struct {
		pattern   string
		str       string
		isPattern bool
		isMatch   bool
	}{
		{"user:bob", "user:alice", true, false},
		{".*", "user:alice", true, true},
		{`group:g\d+`, "group:g10", true, true},
		{`group:g\d+`, "user:alice", true, false},
	}

	for _, test := range tests {
		assert.Equal(t, test.isPattern, m.IsPattern(test.pattern), test.pattern, test.str)
		assert.Equal(t, test.isMatch, m.Match(test.str, test.pattern), test.pattern, test.str)
	}

}

func TestPrefixMatcher(t *testing.T) {

	m := NewPrefixMatcher("re:", RegexMatch)

	tests := []struct {
		pattern   string
		str       string
		isPattern bool
		isMatch   bool
	}{
		{".*", "user:alice", false, false},
		{"re:.*", "user:alice", true, true},
		{`re:group:g\d+`, "group:g10", true, true},
		{`re:group:g\d+`, "user:alice", true, false},
	}

	for _, test := range tests {
		assert.Equal(t, test.isPattern, m.IsPattern(test.pattern), test.pattern, test.str)
		assert.Equal(t, test.isMatch, m.Match(test.str, test.pattern), test.pattern, test.str)
	}
}
