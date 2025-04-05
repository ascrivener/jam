package asntypes

import (
	"encoding/json"
	"io/ioutil"
)

// ParseTestCase parses a test case from a JSON file
func ParseTestCase(filePath string) (*TestCase, error) {
	data, err := ioutil.ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	var testCase TestCase
	if err := json.Unmarshal(data, &testCase); err != nil {
		return nil, err
	}

	return &testCase, nil
}
