package model

import (
	"fmt"
	"strings"
	"testing"
)

func genEffects(effects []Effect, n int) ([]Effect, []Rule) {
	e := make([]Effect, 0)
	m := make([]Rule, 0)

	for i := 0; i < n; i++ {
		e = append(e, effects[i%len(effects)])
		m = append(m, strings.Split(fmt.Sprintf("sub%d,obj%d,act%d", i, i, i), ","))
	}
	return e, m
}

func testMerge(t *testing.T, e Effector, effects []Effect, matches []Rule, complete bool, exprected Effect) {
	t.Helper()
	effect, _, err := e.MergeEffects(effects, matches, complete)
	if err != nil {
		t.Error(err.Error())
	}
	if effect != exprected {
		t.Errorf("%d supposed to be %d", effect, exprected)
	}
}

func TestSomeAllow(t *testing.T) {
	e := NewDefaultEffector("e", "some(where (p.eft == allow))")

	effects, matches := genEffects([]Effect{Allow}, 1)
	testMerge(t, e, effects, matches, false, Allow)
	effects, matches = genEffects([]Effect{Deny}, 1)
	testMerge(t, e, effects, matches, false, Indeterminate)
	effects, matches = genEffects([]Effect{}, 0)
	testMerge(t, e, effects, matches, true, Deny)
}

func TestNoDeny(t *testing.T) {
	e := NewDefaultEffector("e", "!some(where (p.eft == deny))")

	effects, matches := genEffects([]Effect{Allow}, 1)
	testMerge(t, e, effects, matches, false, Indeterminate)
	effects, matches = genEffects([]Effect{Deny}, 1)
	testMerge(t, e, effects, matches, false, Deny)
	effects, matches = genEffects([]Effect{}, 0)
	testMerge(t, e, effects, matches, true, Allow)
}

func TestSomeAllowNoDeny(t *testing.T) {
	e := NewDefaultEffector("e", "some(where (p.eft == allow)) && !some(where (p.eft == deny))")

	effects, matches := genEffects([]Effect{Allow}, 1)
	testMerge(t, e, effects, matches, false, Indeterminate)
	effects, matches = genEffects([]Effect{Deny}, 1)
	testMerge(t, e, effects, matches, false, Deny)
	effects, matches = genEffects([]Effect{}, 0)
	testMerge(t, e, effects, matches, true, Deny)
	effects, matches = genEffects([]Effect{Allow}, 1)
	testMerge(t, e, effects, matches, true, Allow)
}
