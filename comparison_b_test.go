package fastac

import (
	"fmt"
	"testing"

	casbin "github.com/casbin/casbin/v2"
)

type AddRulesAPI interface {
	AddRule(params ...string) (bool, error)
}

type CasbinEnforcer struct {
	*casbin.Enforcer
}

func NewCasbinEnforcer(params ...interface{}) (*CasbinEnforcer, error) {
	e := CasbinEnforcer{}
	enforcer, err := casbin.NewEnforcer(params...)
	e.Enforcer = enforcer
	return &e, err
}

func (e *CasbinEnforcer) AddRule(params ...string) (bool, error) {
	key := params[0]
	sec := key[0]
	switch sec {
	case 'p':
		return e.AddNamedPolicy(key, params[1:])
	case 'g':
		return e.AddNamedGroupingPolicy(key, params[1:])
	}
	return false, fmt.Errorf("unknown sec: %d", sec)
}

func genRBACPolicy(e AddRulesAPI, n int) error {
	for i := 0; i < n; i++ {
		_, err := e.AddRule("g", fmt.Sprintf("user%d", i), fmt.Sprintf("group%d", i/10))
		if err != nil {
			return err
		}
	}

	for i := 0; i < n/10; i++ {
		_, err := e.AddRule("p", fmt.Sprintf("group%d", i), fmt.Sprintf("data%d", i/10), "read")
		if err != nil {
			return err
		}
	}
	return nil
}

func genABACPolicy(e AddRulesAPI, n int) error {
	for i := 0; i < n; i++ {
		_, err := e.AddRule("p", fmt.Sprintf("r.sub.Age > %d", i%100), fmt.Sprintf("data%d", i), "read")
		if err != nil {
			return err
		}
	}
	return nil
}

func TestRBACBenchmarkPolicy(t *testing.T) {
	e, _ := NewEnforcer("examples/rbac_model.conf")
	if err := genRBACPolicy(e, 1000); err != nil {
		t.Fatal()
	}
	testEnforce(t, e, "user501", "data9", "read", false)
	testEnforce(t, e, "user501", "data5", "read", true)

	e, _ = NewEnforcer("examples/rbac_model_index.conf")
	if err := genRBACPolicy(e, 1000); err != nil {
		t.Fatal()
	}
	testEnforce(t, e, "user501", "data9", "read", false)
	testEnforce(t, e, "user501", "data5", "read", true)
}

func BenchmarkRBAC(b *testing.B) {
	benchmarks := []struct {
		name   string
		nUsers int
	}{
		{name: "Large", nUsers: 100000},
		{name: "Medium", nUsers: 10000},
		{name: "Small", nUsers: 1000},
	}

	for _, bm := range benchmarks {
		b.Run("size="+bm.name, func(b *testing.B) {
			b.Run("enforcer=casbin", func(b *testing.B) {
				e, _ := NewCasbinEnforcer("examples/rbac_model.conf", false)

				if err := genRBACPolicy(e, bm.nUsers); err != nil {
					b.Fatal()
				}

				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					_, _ = e.Enforce("user501", "data9", "read")
				}
			})
			b.Run("enforcer=fastac", func(b *testing.B) {
				e, _ := NewEnforcer("examples/rbac_model.conf")

				if err := genRBACPolicy(e, bm.nUsers); err != nil {
					b.Fatal()
				}

				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					_, _ = e.Enforce("user501", "data9", "read")
				}
			})
			b.Run("enforcer=fastac-index", func(b *testing.B) {
				e, _ := NewEnforcer("examples/rbac_model_index.conf")

				if err := genRBACPolicy(e, bm.nUsers); err != nil {
					b.Fatal()
				}

				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					_, _ = e.Enforce("user501", "data9", "read")
				}
			})
		})
	}
}

func BenchmarkAddPolicy(b *testing.B) {
	benchmarks := []struct {
		name string
		size int
	}{
		{name: "Large", size: 100000},
		{name: "Medium", size: 10000},
		{name: "Empty", size: 0},
	}

	for _, bm := range benchmarks {
		b.Run("size="+bm.name, func(b *testing.B) {
			b.Run("enforcer=casbin", func(b *testing.B) {
				e, _ := NewCasbinEnforcer("examples/rbac_model.conf", false)

				if err := genRBACPolicy(e, bm.size); err != nil {
					b.Fatal()
				}

				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					_, _ = e.AddPolicy(fmt.Sprintf("group%d", i), fmt.Sprintf("data%d", i/10), "write")
				}
			})
			b.Run("enforcer=fastac", func(b *testing.B) {
				e, _ := NewEnforcer("examples/rbac_model.conf")

				if err := genRBACPolicy(e, bm.size); err != nil {
					b.Fatal()
				}

				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					_, _ = e.AddRule("p", fmt.Sprintf("group%d", i), fmt.Sprintf("data%d", i/10), "write")
				}
			})
			b.Run("enforcer=fastac-index", func(b *testing.B) {
				e, _ := NewEnforcer("examples/rbac_model_index.conf")

				if err := genRBACPolicy(e, bm.size); err != nil {
					b.Fatal()
				}

				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					_, _ = e.AddRule("p", fmt.Sprintf("group%d", i), fmt.Sprintf("data%d", i/10), "write")
				}
			})
		})
	}
}

func BenchmarkABAC(b *testing.B) {

	benchmarks := []struct {
		name string
		n    int
	}{
		{name: "Large", n: 1000},
		{name: "Medium", n: 100},
		{name: "Small", n: 10},
	}

	sub := struct {
		Age int
	}{
		Age: 16,
	}

	for _, bm := range benchmarks {
		b.Run("size="+bm.name, func(b *testing.B) {
			b.Run("enforcer=casbin", func(b *testing.B) {
				e, _ := NewCasbinEnforcer("examples/abac_rule_model.conf", false)

				if err := genABACPolicy(e, bm.n); err != nil {
					b.Fatal()
				}

				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					_, _ = e.Enforce(sub, "data50", "read")
				}
			})
			b.Run("enforcer=fastac", func(b *testing.B) {
				e, _ := NewEnforcer("examples/abac_rule_model.conf")

				if err := genABACPolicy(e, bm.n); err != nil {
					b.Fatal()
				}

				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					_, _ = e.Enforce(sub, "data50", "read")
				}
			})
			b.Run("enforcer=fastac-index", func(b *testing.B) {
				e, _ := NewEnforcer("examples/abac_rule_model_index.conf")

				if err := genABACPolicy(e, bm.n); err != nil {
					b.Fatal()
				}

				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					_, _ = e.Enforce(sub, "data50", "read")
				}
			})
		})
	}
}
