package adapter

import (
	"bufio"
	"errors"
	"os"

	"example.com/fastac/api"
)

type FileAdapter struct {
	path string
}

func NewFileAdapter(path string) *FileAdapter {
	return &FileAdapter{path: path}
}

func (a *FileAdapter) LoadPolicy(model api.IAddRuleBool) error {
	file, err := os.Open(a.path)
	if err != nil {
		return err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		LoadPolicyLine(scanner.Text(), model)
	}

	return scanner.Err()
}

func (a *FileAdapter) SavePolicy(model *api.IRangeRules) error {
	return errors.New("not implemented")
}

func (a *FileAdapter) AddPolicy(sec string, key string, rule []string) error {
	return errors.New("not implemented")
}

func (a *FileAdapter) RemovePolicy(sec string, key string, rule []string) error {
	return errors.New("not implemented")
}
