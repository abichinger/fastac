package adapter

import (
	"os"
	"testing"
)

func TestFileAdapter(t *testing.T) {
	a := NewFileAdapter("test.csv")
	defer os.Remove("test.csv")

	BasicAdapterTest(t, a)
}
