package guard

import (
	"reflect"
	"strings"
	"unicode"
)

// sensitiveNames are lower-case substrings of a field or key name whose value
// is blanked by RedactConfig.
var sensitiveNames = []string{
	"password", "passwd", "passphrase", "secret", "token", "privatekey", "private_key",
	"apikey", "api_key", "credential", "authkey", "auth_key",
}

// sensitiveWords are whole words (see nameWords) that denote a secret. They are
// matched as words, not as substrings, so "Pass" and "PW" are secrets while
// "Bypass", "Compass" and "Passive" (an FTP mode) are not.
var sensitiveWords = map[string]bool{
	"pass": true, "pwd": true, "pw": true, "cookie": true, "cookies": true,
	"authorization": true, "bearer": true,
}

// keyQualifiers are the words that make a "key" a secret key: "PrivKey",
// "SSHKey", "SigningKey", "AccessKey" are secrets; "HostKey" (a pinned public
// host key), "PublicKey" and "KeyFile" are not.
var keyQualifiers = map[string]bool{
	"priv": true, "private": true, "secret": true, "api": true, "auth": true, "access": true,
	"signing": true, "ssh": true, "session": true, "encryption": true, "master": true,
}

// maxRedactDepth bounds the recursion of RedactConfig (nested structs, pointer
// cycles). A value nested deeper is blanked, not copied: fail closed.
const maxRedactDepth = 12

// nameWords splits a field or key name into lower-case words at separators,
// at lower-to-upper case changes and at letter/digit changes ("APIKey" is
// "api", "key"; "private_key" is "private", "key").
func nameWords(name string) []string {
	rs := []rune(name)
	var out []string
	var cur []rune
	flush := func() {
		if len(cur) > 0 {
			out = append(out, strings.ToLower(string(cur)))
			cur = cur[:0]
		}
	}
	for i, r := range rs {
		if !unicode.IsLetter(r) && !unicode.IsDigit(r) {
			flush()
			continue
		}
		if i > 0 && len(cur) > 0 {
			prev := rs[i-1]
			switch {
			case unicode.IsLower(prev) && unicode.IsUpper(r):
				flush()
			case unicode.IsUpper(prev) && unicode.IsUpper(r) && i+1 < len(rs) && unicode.IsLower(rs[i+1]):
				flush() // "APIKey": split before the "K"
			case unicode.IsDigit(prev) != unicode.IsDigit(r):
				flush()
			}
		}
		cur = append(cur, r)
	}
	flush()
	return out
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
	words := nameWords(name)
	hasKey, qualified := false, false
	for _, w := range words {
		if sensitiveWords[w] {
			return true
		}
		if w == "key" || w == "keys" {
			hasKey = true
		}
		if keyQualifiers[w] {
			qualified = true
		}
	}
	return hasKey && qualified
}

// RedactConfig returns a deep, defensive copy of a client configuration with
// every secret blanked: the result cannot be used to build a client with the
// same credentials, and mutating any part of it cannot reach the client the
// config came from.
//
// Handled shapes: a struct, a pointer to a struct and a map with string keys at
// the top level; below that structs, pointers, interfaces, maps, slices and
// arrays are copied recursively (to maxRedactDepth levels, deeper values are
// blanked). A field whose name denotes a secret (see IsSensitiveName) is set to
// its zero value at ANY depth; map entries with a secret key are removed at any
// depth; funcs, channels and unsafe pointers (live handles) are blanked. Any
// other top-level value (nil, string, ...) is returned unchanged.
//
// Limits: unexported fields are copied as they are, so a pointer hidden inside
// one is shared (the guarantee covers the exported surface); a secret stored
// under a non-secret NAME (a field called "Data" holding a password) cannot be
// recognised by name; the allow-list approach (a protocol client returning its
// own PublicConfig, as pkg/ftp and pkg/sftp do) is stronger than any name list.
func RedactConfig(cfg interface{}) interface{} {
	if cfg == nil {
		return nil
	}
	v := reflect.ValueOf(cfg)
	switch v.Kind() {
	case reflect.Ptr:
		if v.IsNil() || v.Elem().Kind() != reflect.Struct {
			return cfg
		}
		return redact(v, 0).Interface()
	case reflect.Struct:
		return redact(v, 0).Interface()
	case reflect.Map:
		if v.IsNil() {
			return cfg
		}
		return redact(v, 0).Interface()
	}
	return cfg
}

func isSensitiveKey(k reflect.Value) bool {
	if k.Kind() == reflect.Interface && !k.IsNil() {
		k = k.Elem()
	}
	return k.Kind() == reflect.String && IsSensitiveName(k.String())
}

// redact returns a deep copy of v (same type) with secrets blanked.
func redact(v reflect.Value, depth int) reflect.Value {
	t := v.Type()
	if depth > maxRedactDepth {
		return reflect.Zero(t)
	}
	switch v.Kind() {
	case reflect.Ptr:
		if v.IsNil() {
			return reflect.Zero(t)
		}
		cp := reflect.New(t.Elem())
		cp.Elem().Set(redact(v.Elem(), depth+1))
		return cp
	case reflect.Interface:
		if v.IsNil() {
			return reflect.Zero(t)
		}
		out := reflect.New(t).Elem()
		out.Set(redact(v.Elem(), depth+1))
		return out
	case reflect.Struct:
		cp := reflect.New(t).Elem()
		cp.Set(v) // unexported fields are copied as they are
		for i := 0; i < t.NumField(); i++ {
			f := t.Field(i)
			if !f.IsExported() {
				continue
			}
			if IsSensitiveName(f.Name) {
				cp.Field(i).Set(reflect.Zero(f.Type))
				continue
			}
			cp.Field(i).Set(redact(v.Field(i), depth+1))
		}
		return cp
	case reflect.Map:
		if v.IsNil() {
			return reflect.Zero(t)
		}
		out := reflect.MakeMapWithSize(t, v.Len())
		it := v.MapRange()
		for it.Next() {
			k := it.Key()
			if isSensitiveKey(k) {
				continue
			}
			out.SetMapIndex(k, redact(it.Value(), depth+1))
		}
		return out
	case reflect.Slice:
		if v.IsNil() {
			return reflect.Zero(t)
		}
		out := reflect.MakeSlice(t, v.Len(), v.Len())
		for i := 0; i < v.Len(); i++ {
			out.Index(i).Set(redact(v.Index(i), depth+1))
		}
		return out
	case reflect.Array:
		out := reflect.New(t).Elem()
		for i := 0; i < v.Len(); i++ {
			out.Index(i).Set(redact(v.Index(i), depth+1))
		}
		return out
	case reflect.Chan, reflect.Func, reflect.UnsafePointer:
		return reflect.Zero(t)
	}
	return v
}
