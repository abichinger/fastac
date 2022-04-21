package effector

import (
	"fmt"
	"strings"
	"testing"

	"github.com/abichinger/fastac/model/eft"
	"github.com/abichinger/fastac/model/types"
)

func genEffects(effects []types.Effect, n int) ([]types.Effect, []types.Rule) {
	e := make([]types.Effect, 0)
	m := make([]types.Rule, 0)

	for i := 0; i < n; i++ {
		e = append(e, effects[i%len(effects)])
		m = append(m, strings.Split(fmt.Sprintf("sub%d,obj%d,act%d", i, i, i), ","))
	}
	return e, m
}

func testMerge(t *testing.T, e Effector, effects []types.Effect, matches []types.Rule, complete bool, exprected types.Effect) {
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

	effects, matches := genEffects([]types.Effect{eft.Allow}, 1)
	testMerge(t, e, effects, matches, false, eft.Allow)
	effects, matches = genEffects([]types.Effect{eft.Deny}, 1)
	testMerge(t, e, effects, matches, false, eft.Indeterminate)
	effects, matches = genEffects([]types.Effect{}, 0)
	testMerge(t, e, effects, matches, true, eft.Deny)
}

func TestNoDeny(t *testing.T) {
	e := NewDefaultEffector("e", "!some(where (p.eft == deny))")

	effects, matches := genEffects([]types.Effect{eft.Allow}, 1)
	testMerge(t, e, effects, matches, false, eft.Indeterminate)
	effects, matches = genEffects([]types.Effect{eft.Deny}, 1)
	testMerge(t, e, effects, matches, false, eft.Deny)
	effects, matches = genEffects([]types.Effect{}, 0)
	testMerge(t, e, effects, matches, true, eft.Allow)
}

func TestSomeAllowNoDeny(t *testing.T) {
	e := NewDefaultEffector("e", "some(where (p.eft == allow)) && !some(where (p.eft == deny))")

	effects, matches := genEffects([]types.Effect{eft.Allow}, 1)
	testMerge(t, e, effects, matches, false, eft.Indeterminate)
	effects, matches = genEffects([]types.Effect{eft.Deny}, 1)
	testMerge(t, e, effects, matches, false, eft.Deny)
	effects, matches = genEffects([]types.Effect{}, 0)
	testMerge(t, e, effects, matches, true, eft.Deny)
	effects, matches = genEffects([]types.Effect{eft.Allow}, 1)
	testMerge(t, e, effects, matches, true, eft.Allow)
}
