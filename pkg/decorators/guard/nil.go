// Package guard holds the small helpers shared by the decorators and the
// connection fabric: typed-nil detection, config redaction and
// capability-preserving stream wrappers. It exists so that the two packages do
// not carry diverging copies of the same logic.
package guard

import "reflect"

// IsNil reports whether v is nil or an interface holding a nil pointer, map,
// slice, func or chan (a "typed nil"). A typed-nil client passes a plain
// `== nil` check and then panics on first use; the decorators refuse it at
// construction instead.
func IsNil(v interface{}) bool {
	if v == nil {
		return true
	}
	rv := reflect.ValueOf(v)
	switch rv.Kind() {
	case reflect.Ptr, reflect.Map, reflect.Slice, reflect.Func, reflect.Chan, reflect.Interface, reflect.UnsafePointer:
		return rv.IsNil()
	}
	return false
}
