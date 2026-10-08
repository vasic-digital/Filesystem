package guard

import (
	"reflect"
	"strings"
)

// sensitiveNames are lower-case substrings of a field or key name whose value
// is blanked by RedactConfig.
var sensitiveNames = []string{
	"password", "passwd", "passphrase", "secret", "token", "privatekey", "private_key",
	"apikey", "api_key", "credential", "authkey", "auth_key",
}

// IsSensitiveName reports whether a config field or settings key name denotes
// a secret.
func IsSensitiveName(name string) bool {
	low := strings.ToLower(name)
	for _, s := range sensitiveNames {
		if strings.Contains(low, s) {
			return true
		}
	}
	return false
}

// RedactConfig returns a defensive copy of a client configuration with every
// secret blanked: the result cannot be used to build a client with the same
// credentials, and mutating it cannot reach the client the config came from.
//
// Handled shapes: a struct, a pointer to a struct and a map with string keys
// (one level of nested maps/slices of such maps is copied too). A field whose
// name denotes a secret (see IsSensitiveName) is set to its zero value; map
// entries with a secret key are removed. Any other value (nil, string, ...) is
// returned unchanged. Pointers hidden inside unexported fields are shared, not
// copied: the guarantee covers the exported surface only.
func RedactConfig(cfg interface{}) interface{} {
	if cfg == nil {
		return nil
	}
	v := reflect.ValueOf(cfg)
	switch v.Kind() {
	case reflect.Ptr:
		if v.IsNil() {
			return cfg
		}
		if v.Elem().Kind() != reflect.Struct {
			return cfg
		}
		cp := reflect.New(v.Elem().Type())
		cp.Elem().Set(v.Elem())
		redactStruct(cp.Elem())
		return cp.Interface()
	case reflect.Struct:
		cp := reflect.New(v.Type()).Elem()
		cp.Set(v)
		redactStruct(cp)
		return cp.Interface()
	case reflect.Map:
		if v.IsNil() {
			return cfg
		}
		return redactMap(v).Interface()
	}
	return cfg
}

func redactStruct(s reflect.Value) {
	t := s.Type()
	for i := 0; i < s.NumField(); i++ {
		f := t.Field(i)
		if !f.IsExported() {
			continue
		}
		fv := s.Field(i)
		if IsSensitiveName(f.Name) {
			fv.Set(reflect.Zero(fv.Type()))
			continue
		}
		switch fv.Kind() {
		case reflect.Map:
			if !fv.IsNil() {
				fv.Set(redactMap(fv))
			}
		case reflect.Slice:
			if !fv.IsNil() {
				fv.Set(copySlice(fv))
			}
		}
	}
}

func redactMap(m reflect.Value) reflect.Value {
	out := reflect.MakeMapWithSize(m.Type(), m.Len())
	it := m.MapRange()
	for it.Next() {
		k, val := it.Key(), it.Value()
		if k.Kind() == reflect.String && IsSensitiveName(k.String()) {
			continue
		}
		if val.Kind() == reflect.Interface && !val.IsNil() {
			val = val.Elem()
		}
		switch val.Kind() {
		case reflect.Map:
			if !val.IsNil() {
				val = redactMap(val)
			}
		case reflect.Slice:
			if !val.IsNil() {
				val = copySlice(val)
			}
		}
		if it.Value().Kind() == reflect.Interface {
			nv := reflect.New(m.Type().Elem()).Elem()
			nv.Set(val)
			val = nv
		}
		out.SetMapIndex(k, val)
	}
	return out
}

func copySlice(s reflect.Value) reflect.Value {
	out := reflect.MakeSlice(s.Type(), s.Len(), s.Len())
	reflect.Copy(out, s)
	return out
}
