package util

import "strings"

func Join2D(elems [][]string, sep string) []string {
	res := []string{}
	for _, elem := range elems {
		res = append(res, strings.Join(elem, sep))
	}
	return res
}
