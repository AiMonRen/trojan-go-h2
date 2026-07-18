package config

import (
	"context"
	"strings"
	"testing"

	"github.com/voidluo/trojan-go/common"
)

type Foo struct {
	Field1 string `json,yaml:"field1"`
	Field2 bool   `json:"field2" yaml:"field2"`
}

type TestStruct struct {
	Field1 string `json,yaml:"field1"`
	Field2 bool   `json,yaml:"field2"`
	Field3 []Foo  `json,yaml:"field3"`
}

func creator() any {
	return &TestStruct{}
}

func TestJSONConfig(t *testing.T) {
	RegisterConfigCreator("test", creator)
	data := []byte(`
	{
		"field1": "test1",
		"field2": true,
		"field3": [
			{
				"field1": "aaaa",
				"field2": true
			}
		]
	}
	`)
	ctx, err := WithJSONConfig(context.Background(), data)
	common.Must(err)
	c := FromContext(ctx, "test").(*TestStruct)
	if c.Field1 != "test1" || c.Field2 != true {
		t.Fail()
	}
}

func TestYAMLConfig(t *testing.T) {
	RegisterConfigCreator("test", creator)
	data := []byte(`
field1: 012345678
field2: true
field3:
  - field1: test
    field2: true
`)
	ctx, err := WithYAMLConfig(context.Background(), data)
	common.Must(err)
	c := FromContext(ctx, "test").(*TestStruct)
	if c.Field1 != "012345678" || c.Field2 != true || c.Field3[0].Field1 != "test" {
		t.Fail()
	}
}

type AdminConfig struct {
	Path    string
	SubPath string
}

func adminCreator() any {
	return &AdminConfig{}
}

func TestSubPathAutoGeneration(t *testing.T) {
	RegisterConfigCreator("AdminConfig", adminCreator)
	data := []byte(`{}`)
	ctx, err := WithJSONConfig(context.Background(), data)
	if err != nil {
		t.Fatalf("Failed to parse config: %v", err)
	}
	c := FromContext(ctx, "AdminConfig").(*AdminConfig)

	// 验证 Path 是否被强制清洗为 "/admin/"
	if c.Path != "/admin/" {
		t.Errorf("Path expected /admin/, got %s", c.Path)
	}

	// 验证 SubPath 是否被自动生成且符合前缀 /sub-
	if !strings.HasPrefix(c.SubPath, "/sub-") {
		t.Errorf("SubPath expected prefix /sub-, got %s", c.SubPath)
	}
	if len(c.SubPath) != 13 { // "/sub-" (5 chars) + 8 chars random
		t.Errorf("SubPath expected length 13, got %d (value: %s)", len(c.SubPath), c.SubPath)
	}
}
