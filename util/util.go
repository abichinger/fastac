package util

import (
	"errors"
	"os"
	"strings"
)

const DefaultSep = ","

func Join2D(elems [][]string, sep string) []string {
	res := []string{}
	for _, elem := range elems {
		res = append(res, strings.Join(elem, sep))
	}
	return res
}

func FileExists(path string) (bool, error) {
	var err error
	if _, err = os.Stat(path); err == nil {
		return true, nil
	} else if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	return false, err
}

func Hash(rule []string) string {
	return strings.Join(rule, DefaultSep)
}
