package zip

import (
	"fmt"
	"reflect"
	"strconv"
	"strings"
)

// validate runs minimal struct-tag validation: required, min=N, max=N,
// minlen=N, maxlen=N. Operates on string / numeric / slice fields.
// Anything else passes through.
//
// This is deliberately not a full validator (no `github.com/go-playground/validator`
// — we don't want the dependency). It covers ~90% of REST API input
// validation needs and is ~120 LOC.
func validate(v any) error {
	val := reflect.ValueOf(v)
	if val.Kind() == reflect.Pointer {
		if val.IsNil() {
			return nil
		}
		val = val.Elem()
	}
	if val.Kind() != reflect.Struct {
		return nil
	}
	t := val.Type()
	for i := 0; i < t.NumField(); i++ {
		field := t.Field(i)
		tag := field.Tag.Get("validate")
		if tag == "" || tag == "-" {
			continue
		}
		if err := validateField(field.Name, val.Field(i), tag); err != nil {
			return err
		}
	}
	return nil
}

func validateField(name string, val reflect.Value, tag string) error {
	rules := strings.Split(tag, ",")
	for _, r := range rules {
		r = strings.TrimSpace(r)
		if r == "" {
			continue
		}
		var key, raw string
		if i := strings.IndexByte(r, '='); i >= 0 {
			key, raw = r[:i], r[i+1:]
		} else {
			key = r
		}
		switch key {
		case "required":
			if isZero(val) {
				return fmt.Errorf("field %q is required", name)
			}
		case "min":
			n, err := strconv.Atoi(raw)
			if err != nil {
				return fmt.Errorf("field %q invalid min=%q", name, raw)
			}
			if !checkMin(val, n) {
				return fmt.Errorf("field %q must be >= %d", name, n)
			}
		case "max":
			n, err := strconv.Atoi(raw)
			if err != nil {
				return fmt.Errorf("field %q invalid max=%q", name, raw)
			}
			if !checkMax(val, n) {
				return fmt.Errorf("field %q must be <= %d", name, n)
			}
		case "minlen":
			n, err := strconv.Atoi(raw)
			if err != nil {
				return fmt.Errorf("field %q invalid minlen=%q", name, raw)
			}
			if !checkLenMin(val, n) {
				return fmt.Errorf("field %q length must be >= %d", name, n)
			}
		case "maxlen":
			n, err := strconv.Atoi(raw)
			if err != nil {
				return fmt.Errorf("field %q invalid maxlen=%q", name, raw)
			}
			if !checkLenMax(val, n) {
				return fmt.Errorf("field %q length must be <= %d", name, n)
			}
		}
	}
	return nil
}

func isZero(v reflect.Value) bool {
	switch v.Kind() {
	case reflect.String:
		return v.Len() == 0
	case reflect.Slice, reflect.Map, reflect.Array:
		return v.Len() == 0
	case reflect.Pointer, reflect.Interface:
		return v.IsNil()
	}
	return v.IsZero()
}

func checkMin(v reflect.Value, n int) bool {
	switch v.Kind() {
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return v.Int() >= int64(n)
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return v.Uint() >= uint64(n)
	case reflect.Float32, reflect.Float64:
		return v.Float() >= float64(n)
	}
	return true
}

func checkMax(v reflect.Value, n int) bool {
	switch v.Kind() {
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return v.Int() <= int64(n)
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return v.Uint() <= uint64(n)
	case reflect.Float32, reflect.Float64:
		return v.Float() <= float64(n)
	}
	return true
}

func checkLenMin(v reflect.Value, n int) bool {
	switch v.Kind() {
	case reflect.String, reflect.Slice, reflect.Map, reflect.Array:
		return v.Len() >= n
	}
	return true
}

func checkLenMax(v reflect.Value, n int) bool {
	switch v.Kind() {
	case reflect.String, reflect.Slice, reflect.Map, reflect.Array:
		return v.Len() <= n
	}
	return true
}
