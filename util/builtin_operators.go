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
	"errors"
	"fmt"
	"net"
	"path"
	"reflect"
	"regexp"
	"runtime"
	"strings"

	"github.com/abichinger/govaluate"
	pm "github.com/abichinger/pathmatch"
)

type MatchingFunc func(str, pattern string) bool

type IMatcher interface {
	IsPattern(str string) bool
	Match(str, pattern string) bool
}

type Matcher struct {
	patternFn func(str string) bool
	matchFn   MatchingFunc
}

func NewMatcher(isPatternFn func(str string) bool, matchFn MatchingFunc) *Matcher {
	return &Matcher{isPatternFn, matchFn}
}

func (m *Matcher) IsPattern(str string) bool {
	return m.patternFn(str)
}
func (m *Matcher) Match(str, pattern string) bool {
	return m.matchFn(str, pattern)
}

type PrefixMatcher struct {
	prefix  string
	matchFn MatchingFunc
}

func NewPrefixMatcher(prefix string, matchFn MatchingFunc) *PrefixMatcher {
	return &PrefixMatcher{prefix, matchFn}
}

func (m *PrefixMatcher) IsPattern(str string) bool {
	return strings.HasPrefix(str, m.prefix)
}
func (m *PrefixMatcher) Match(str, pattern string) bool {
	if m.IsPattern(pattern) {
		return m.matchFn(str, pattern[len(m.prefix):])
	}
	return false
}

// validate the variadic parameter size and type as string
func ValidateVariadicArgs(expectedLen int, args ...interface{}) error {
	if len(args) != expectedLen {
		return fmt.Errorf("Expected %d arguments, but got %d", expectedLen, len(args))
	}

	for _, p := range args {
		_, ok := p.(string)
		if !ok {
			return errors.New("Argument must be a string")
		}
	}

	return nil
}

// RegexMatch determines whether key1 matches the pattern of key2 in regular expression.
func RegexMatch(key1 string, key2 string) bool {
	res, err := regexp.MatchString(key2, key1)
	if err != nil {
		panic(err)
	}
	return res
}

// IPMatch determines whether IP address ip1 matches the pattern of IP address ip2, ip2 can be an IP address or a CIDR pattern.
// For example, "192.168.2.123" matches "192.168.2.0/24"
func IPMatch(ip1 string, ip2 string) bool {
	objIP1 := net.ParseIP(ip1)
	if objIP1 == nil {
		panic("invalid argument: ip1 in IPMatch() function is not an IP address.")
	}

	_, cidr, err := net.ParseCIDR(ip2)
	if err != nil {
		objIP2 := net.ParseIP(ip2)
		if objIP2 == nil {
			panic("invalid argument: ip2 in IPMatch() function is neither an IP address nor a CIDR.")
		}

		return objIP1.Equal(objIP2)
	}

	return cidr.Contains(objIP1)
}

// GlobMatch determines whether key1 matches the pattern of key2 using glob pattern
func GlobMatch(key1 string, key2 string) (bool, error) {
	return path.Match(key2, key1)
}

// GlobMatchFunc is the wrapper for GlobMatch.
func GlobMatchFunc(args ...interface{}) (interface{}, error) {
	if err := ValidateVariadicArgs(2, args...); err != nil {
		return false, fmt.Errorf("%s: %s", "globMatch", err)
	}

	name1 := args[0].(string)
	name2 := args[1].(string)

	return GlobMatch(name1, name2)
}

func WrapMatchingFunc(fn MatchingFunc) govaluate.ExpressionFunction {
	return func(args ...interface{}) (interface{}, error) {
		if err := ValidateVariadicArgs(2, args...); err != nil {
			pc := reflect.ValueOf(fn).Pointer()
			fnName := runtime.FuncForPC(pc).Name()
			fnSplitName := strings.Split(fnName, ".")
			return false, fmt.Errorf("%s: %s", fnSplitName[len(fnSplitName)-1], err)
		}

		name1 := args[0].(string)
		name2 := args[1].(string)

		return bool(fn(name1, name2)), nil
	}
}

var pathMatchCache = NewSyncLRUCache(100)
var pathMatchCache2 = NewSyncLRUCache(100)

func getPath(cache *SyncLRUCache, pattern string, options ...pm.Option) *pm.Path {
	value, ok := cache.Get(pattern)
	var p *pm.Path
	var err error
	if ok {
		p = value.(*pm.Path)
	} else {
		p, err = pm.Compile(pattern, options...)
		if err != nil {
			panic(fmt.Sprintf("compile %s: %s\n", pattern, err.Error()))
		}
		cache.Put(pattern, p)
	}
	return p
}

func PathMatch(path, pattern string) bool {
	p := getPath(pathMatchCache, pattern)
	return p.Match(path)
}

func PathMatch2(path, pattern string) bool {
	p := getPath(pathMatchCache2, pattern, pm.SetPrefix("{"), pm.SetSuffix("}"))
	return p.Match(path)
}

func IsPathPattern(path string) bool {
	p := getPath(pathMatchCache, path)
	return !p.IsStatic()
}

func IsPathPattern2(path string) bool {
	p := getPath(pathMatchCache2, path, pm.SetPrefix("{"), pm.SetSuffix("}"))
	return !p.IsStatic()
}

var PathMatchFunc = WrapMatchingFunc(PathMatch)
var PathMatchFunc2 = WrapMatchingFunc(PathMatch2)
var RegexMatchFunc = WrapMatchingFunc(RegexMatch)
var IPMatchFunc = WrapMatchingFunc(IPMatch)

const defaultPrefix = "p'"

var PathMatcher = NewMatcher(IsPathPattern, PathMatch)
var PathMatcher2 = NewMatcher(IsPathPattern2, PathMatch2)
var RegexMatcher = NewPrefixMatcher(defaultPrefix, RegexMatch)
