package fastac_test

import (
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/abichinger/fastac"
	gormadapter "github.com/abichinger/gorm-adapter"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

var example_rules_1 = [][]string{
	{"p", "alice", "data1", "read"},
	{"p", "alice", "data1", "write"},
	{"p", "bob", "data1", "read"},
}

func createDB(name string) *gorm.DB {
	_ = os.Mkdir(".tmp", 0755)
	db, _ := gorm.Open(sqlite.Open(".tmp/"+name+".db"), &gorm.Config{})
	return db
}

func removeDB(name string) {
	os.Remove(".tmp/" + name + ".db")
}

// ExampleStorageAdapter shows how to store/load policy rules to/from a storage adapter
func Example_storageAdapter() {

	//init adapter
	db := createDB("example")
	defer removeDB("example")
	a, err := gormadapter.NewAdapter(db)
	if err != nil {
		panic(err)
	}

	//create enforcer and store rules using the autosave feature
	e, _ := fastac.NewEnforcer("examples/basic_model.conf", a, fastac.OptionAutosave(true))
	err = e.AddRules(example_rules_1)
	if err != nil {
		panic(err)
	}

	//second enforcer to demonstrate LoadPolicy
	e2, _ := fastac.NewEnforcer("examples/basic_model.conf", a)
	err = e2.LoadPolicy()
	if err != nil {
		panic(err)
	}

	loadedRules := []string{}
	e2.GetModel().RangeRules(func(rule []string) bool {
		loadedRules = append(loadedRules, strings.Join(rule, ", "))
		return true
	})

	sort.Strings(loadedRules)
	for _, rule := range loadedRules {
		fmt.Println(rule)
	}
	// Output: p, alice, data1, read
	// p, alice, data1, write
	// p, bob, data1, read
}
