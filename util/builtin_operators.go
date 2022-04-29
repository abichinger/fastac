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
)

type MatchingFunc func(str, pattern string) bool

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

func PrefixDecorator(prefix string, fn MatchingFunc) MatchingFunc {
	return func(str, pattern string) bool {
		if strings.HasPrefix(pattern, prefix) {
			return fn(str, pattern)
		} else {
			return false
		}
	}
}

func nextSegment(path, sep string) (seg string, remaining string, last bool) {
	i := strings.Index(path, sep)
	if i == -1 {
		return path, "", true
	}
	return path[:i], path[i+1:], false
}

func isDynamicSegment(segment string, prefix, suffix byte) bool {
	l := len(segment)
	if l == 0 {
		return false
	}
	return (prefix == 0 || segment[0] == prefix) &&
		(suffix == 0 || segment[l-1] == suffix)
}

func PathMatchHelper(path, pattern, sep string, prefix, suffix byte) bool {
	if path == pattern || pattern == "*" {
		return true
	}

	var pathS, patternS string
	var lastPathSeg, lastPatternSeg bool
	pathS, path, lastPathSeg = nextSegment(path, sep)
	patternS, pattern, lastPatternSeg = nextSegment(pattern, sep)

	if pathS == patternS || isDynamicSegment(patternS, prefix, suffix) {
		if lastPathSeg != lastPatternSeg {
			return false
		}
		return PathMatchHelper(path, pattern, sep, prefix, suffix)
	}
	if patternS == "*" {
		if !lastPatternSeg && lastPathSeg {
			return false
		}
		return PathMatchHelper(path, pattern, sep, prefix, suffix) ||
			PathMatchHelper(path, "*"+sep+pattern, sep, prefix, suffix)
	}
	return false
}

func PathMatch(path, pattern string) bool {
	return PathMatchHelper(path, pattern, "/", ':', 0)
}

func PathMatch2(path, pattern string) bool {
	return PathMatchHelper(path, pattern, "/", '{', '}')
}

var PathMatchFunc = WrapMatchingFunc(PathMatch)
var PathMatchFunc2 = WrapMatchingFunc(PathMatch2)
var RegexMatchFunc = WrapMatchingFunc(RegexMatch)
var IPMatchFunc = WrapMatchingFunc(IPMatch)

const defaultPrefix = "p'"

var RegexMatchPrefix = PrefixDecorator(defaultPrefix, RegexMatch)
var IPMatchPrefix = PrefixDecorator(defaultPrefix, IPMatch)

//var GlobMatchPrefix = PrefixDecorator(defaultPrefix, GlobMatch)
