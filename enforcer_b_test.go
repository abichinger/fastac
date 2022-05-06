package fastac

import (
	"fmt"
	"testing"
)

func genACL(e *Enforcer, nUsers int, nObjects int, sub string, obj string) {
	for i := 0; i < nUsers; i++ {
		for j := 0; j < nObjects; j++ {
			_, _ = e.AddRule([]string{"p", fmt.Sprintf("%s%d", sub, i), fmt.Sprintf("%s%d", obj, j), "read"})
		}
	}
}

func genACLWithPaths(e *Enforcer, nUsers int, nPaths int, sub string, obj string) {
	for i := 0; i < nUsers; i++ {
		for j := 0; j < nPaths; j++ {
			_, _ = e.AddRule([]string{"p", fmt.Sprintf("%s%d", sub, i), fmt.Sprintf("/%s/%d/resource/:id/%s/%d", sub, i, obj, j), "read"})
		}
	}
}

func genUsers(e *Enforcer, nUsers int, nRoles int, user string, role string) {
	for i := 0; i < nUsers; i++ {
		_, _ = e.AddRule([]string{"g", fmt.Sprintf("%s%d", user, i), fmt.Sprintf("%s%d", role, i%nRoles)})
	}
}

func genABAC(e *Enforcer, nSubRules int, nObjects int, subRule string, obj string) {
	for i := 0; i < nSubRules; i++ {
		for j := 0; j < nObjects; j++ {
			_, _ = e.AddRule([]string{"p", fmt.Sprintf(subRule, i), fmt.Sprintf("%s%d", obj, j), "read"})
		}
	}
}

func BenchmarkACL(b *testing.B) {

	bmUsers := []int{10, 100, 1000}

	bmRules := []int{1000, 10000, 100000}

	for _, nRules := range bmRules {
		b.Run(fmt.Sprintf("rules=%d", nRules), func(b *testing.B) {
			for _, nUsers := range bmUsers {
				nObjects := nRules / nUsers
				b.Run(fmt.Sprintf("users=%d/objects=%d", nUsers, nObjects), func(b *testing.B) {
					e, _ := NewEnforcer("examples/basic_model.conf", nil)
					genACL(e, nUsers, nObjects, "user", "data")

					b.ResetTimer()
					for i := 0; i < b.N; i++ {
						_, _ = e.Enforce("user0", "data", "read") //returns false
					}
				})
			}

		})
	}
}

func BenchmarkACLWithPaths(b *testing.B) {

	bmUsers := []int{10, 100, 1000}

	bmRules := []int{1000, 10000, 100000}

	for _, nRules := range bmRules {
		b.Run(fmt.Sprintf("rules=%d", nRules), func(b *testing.B) {
			for _, nUsers := range bmUsers {
				nObjects := nRules / nUsers
				b.Run(fmt.Sprintf("users=%d/objects=%d", nUsers, nObjects), func(b *testing.B) {
					e, _ := NewEnforcer("examples/pathmatch_model.conf", nil)
					genACLWithPaths(e, nUsers, nObjects, "user", "data")

					b.ResetTimer()
					for i := 0; i < b.N; i++ {
						_, _ = e.Enforce("user0", "/user/0/resource/10/data/foo", "read") //returns false
					}
				})
			}

		})
	}
}

func BenchmarkRBAC(b *testing.B) {
	bmUsers := []int{1000, 10000, 100000}

	bmRoles := []int{10, 100, 1000}

	bmRules := []int{1000, 10000, 100000}

	for _, nRules := range bmRules {
		b.Run(fmt.Sprintf("rules=%d", nRules), func(b *testing.B) {
			for _, nRoles := range bmRoles {
				b.Run(fmt.Sprintf("roles=%d", nRoles), func(b *testing.B) {
					for _, nUsers := range bmUsers {
						nObjects := nRules / nRoles
						b.Run(fmt.Sprintf("users=%d/objects=%d", nUsers, nObjects), func(b *testing.B) {

							e, _ := NewEnforcer("examples/rbac_model.conf", nil)
							genUsers(e, nUsers, nRoles, "user", "role")
							genACL(e, nRoles, nObjects, "role", "data")

							b.ResetTimer()
							for i := 0; i < b.N; i++ {
								_, _ = e.Enforce("role0", "data", "read") //returns false
							}

						})
					}
				})
			}

		})
	}
}

func BenchmarkABAC(b *testing.B) {
	bmRules := []int{1000, 10000, 100000}

	bmSubRules := []int{10, 100, 1000}

	for _, nRules := range bmRules {
		b.Run(fmt.Sprintf("rules=%d", nRules), func(b *testing.B) {
			for _, nSubRules := range bmSubRules {
				nObjects := nRules / nSubRules
				b.Run(fmt.Sprintf("subrules=%d/objects=%d", nSubRules, nObjects), func(b *testing.B) {

					sub := map[string]interface{}{
						"Classification": -1,
					}

					e, _ := NewEnforcer("examples/abac_rule_model.conf", nil)
					genABAC(e, nSubRules, nObjects, "r.sub.Classification > %d", "data")

					b.ResetTimer()
					for i := 0; i < b.N; i++ {
						_, _ = e.Enforce(sub, "data0", "read") //returns false
					}
				})
			}
		})
	}
}
