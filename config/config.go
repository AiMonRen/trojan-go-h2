package config

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"math/rand"
	"reflect"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

var creators = make(map[string]Creator)

// Creator creates a config struct for a module.
type Creator func() any

// normalizer is implemented by configs that need post-processing.
type normalizer interface {
	Normalize()
}

// RegisterConfigCreator registers a config struct for parsing.
func RegisterConfigCreator(name string, creator Creator) {
	creators[name+"_CONFIG"] = creator
}

func compatConfigData(data []byte, isJSON bool) []byte {
	keys := []string{"run-type", "log-level", "log-file", "local-addr", "local-port", "remote-addr", "remote-port", "disable-http-check", "udp-timeout"}
	for _, key := range keys {
		underscore := strings.ReplaceAll(key, "-", "_")
		if isJSON {
			data = bytes.ReplaceAll(data, []byte(`"`+key+`"`), []byte(`"`+underscore+`"`))
		} else {
			data = bytes.ReplaceAll(data, []byte(key+":"), []byte(underscore+":"))
		}
	}
	return data
}

func parseJSON(data []byte) (map[string]any, error) {
	data = compatConfigData(data, true)
	result := make(map[string]any)
	for name, creator := range creators {
		cfg := creator()
		if err := json.Unmarshal(data, cfg); err != nil {
			return nil, err
		}
		normalizeConfig(cfg)
		result[name] = cfg
	}
	return result, nil
}

func parseYAML(data []byte) (map[string]any, error) {
	data = compatConfigData(data, false)
	result := make(map[string]any)
	for name, creator := range creators {
		cfg := creator()
		if err := yaml.Unmarshal(data, cfg); err != nil {
			return nil, err
		}
		normalizeConfig(cfg)
		result[name] = cfg
	}
	return result, nil
}

func WithJSONConfig(ctx context.Context, data []byte) (context.Context, error) {
	configs, err := parseJSON(data)
	if err != nil {
		return ctx, err
	}
	for name, cfg := range configs {
		ctx = context.WithValue(ctx, name, cfg)
	}
	return ctx, nil
}

func WithYAMLConfig(ctx context.Context, data []byte) (context.Context, error) {
	configs, err := parseYAML(data)
	if err != nil {
		return ctx, err
	}
	for name, cfg := range configs {
		ctx = context.WithValue(ctx, name, cfg)
	}
	return ctx, nil
}

func WithConfig(ctx context.Context, name string, cfg any) context.Context {
	return context.WithValue(ctx, name+"_CONFIG", cfg)
}

// FromContext extracts a config from a context.
func FromContext(ctx context.Context, name string) any {
	if ctx == nil {
		return nil
	}
	return ctx.Value(name + "_CONFIG")
}

// Require returns a non-nil configuration of the requested type.
func Require[T any](ctx context.Context, name string) (*T, error) {
	if ctx == nil {
		return nil, fmt.Errorf("%s configuration context is nil", name)
	}
	value := FromContext(ctx, name)
	if value == nil {
		return nil, fmt.Errorf("%s configuration is missing", name)
	}
	cfg, ok := value.(*T)
	if !ok || cfg == nil {
		return nil, fmt.Errorf("%s configuration has type %T, want *%T", name, value, new(T))
	}
	return cfg, nil
}

// normalizeConfig recursively normalizes a configuration.
func normalizeConfig(cfg any) {
	if cfg == nil {
		return
	}
	normalizeValue(reflect.ValueOf(cfg))
}

func normalizeValue(val reflect.Value) {
	if val.Kind() == reflect.Ptr {
		if val.IsNil() {
			return
		}
		val = val.Elem()
	}

	switch val.Kind() {
	case reflect.Struct:
		for i := 0; i < val.NumField(); i++ {
			field := val.Field(i)
			fieldName := val.Type().Field(i).Name
			structName := val.Type().Name()
			if structName == "AdminConfig" {
				if fieldName == "Path" && field.Kind() == reflect.String && field.CanSet() {
					field.SetString("/admin/")
				}
				if fieldName == "SubPath" && field.Kind() == reflect.String && field.CanSet() {
					subPath := field.String()
					if subPath == "" {
						const letters = "abcdefghijklmnopqrstuvwxyz0123456789"
						r := rand.New(rand.NewSource(time.Now().UnixNano()))
						chars := make([]byte, 8)
						for j := range chars {
							chars[j] = letters[r.Intn(len(letters))]
						}
						subPath = "/sub-" + string(chars)
					}
					if !strings.HasPrefix(subPath, "/") {
						subPath = "/" + subPath
					}
					field.SetString(subPath)
				}
			} else if fieldName == "Path" && field.Kind() == reflect.String && field.CanSet() {
				path := field.String()
				if path != "" && !strings.HasPrefix(path, "/") {
					field.SetString("/" + path)
				}
			}
			if field.CanSet() && (field.Kind() == reflect.Struct || field.Kind() == reflect.Ptr || field.Kind() == reflect.Slice || field.Kind() == reflect.Array) {
				normalizeValue(field)
			}
		}
	case reflect.Slice, reflect.Array:
		for i := 0; i < val.Len(); i++ {
			normalizeValue(val.Index(i))
		}
	}
}

var _ normalizer
