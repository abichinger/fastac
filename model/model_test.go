package model

import (
	"io/ioutil"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestToString(t *testing.T) {

	models := []string{"../examples/basic_model.conf", "../examples/rbac_model.conf", "../examples/rbac_model_index.conf", "../examples/multiple_policy_definitions_model.conf"}

	minify := func(s string) string {
		s = strings.ReplaceAll(s, " ", "")
		s = strings.ReplaceAll(s, "\n", "")
		return strings.ReplaceAll(s, "\r", "")
	}

	for _, model := range models {
		m, err := NewModelFromFile(model)
		if err != nil {
			t.Error(err.Error())
		}

		modelStr, readErr := ioutil.ReadFile(model)
		if readErr != nil {
			t.Error(readErr.Error())
		}

		lines := strings.Split(string(modelStr), "\n")
		filteredLines := []string{}
		for _, line := range lines {
			if len(line) == 0 || line[0] == '#' || line[0] == ';' {
				continue
			}
			filteredLines = append(filteredLines, line)
		}

		assert.Equal(t, minify(strings.Join(filteredLines, "")), minify(m.String()))
	}

}
