package defs

import (
	"strconv"
	"strings"
)

const defaultSep = "."

func SplitKey(key string) (string, string) {
	split := strings.Split(key, defaultSep)
	if len(split) <= 1 {
		return split[0], ""
	}
	return split[0], strings.Join(split[1:], defaultSep)
}

func SplitMatcherKey(key string) (string, int) {
	mKey, strIndex := SplitKey(key)
	index, err := strconv.Atoi(strIndex)
	if err != nil {
		return mKey, -1
	}
	return mKey, index
}
