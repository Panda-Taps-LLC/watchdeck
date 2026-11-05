// Package lazyre holds a regular expression that is compiled on first use.
//
// Every package linked into the watchdeck binary must be init-free, because
// the hook is the same binary and package init runs on every hook call
// (CONTRIBUTING, DESIGN §7). A package-level regexp.MustCompile runs at init;
// a lazyre.Regexp declared as a composite literal is static data:
//
//	var nameRe = lazyre.Regexp{Expr: `^[a-z]+$`}
//	...
//	nameRe.MatchString(s) // compiles once, here, under a sync.Once
//
// The expression is compiled with regexp.MustCompile, so an invalid one
// panics at first use instead of at init; each user has tests that exercise
// it.
package lazyre

import (
	"regexp"
	"sync"
)

// Regexp is a regular expression compiled on first use. The zero value is
// not useful; set Expr in a composite literal. A Regexp must not be copied
// after first use.
type Regexp struct {
	Expr string

	once sync.Once
	re   *regexp.Regexp
}

// Get returns the compiled expression, compiling it on the first call.
func (r *Regexp) Get() *regexp.Regexp {
	r.once.Do(func() { r.re = regexp.MustCompile(r.Expr) })
	if r.re == nil { // the first compile panicked and was recovered
		panic("lazyre: " + r.Expr + " failed to compile")
	}
	return r.re
}

// MatchString reports whether s contains any match of the expression.
func (r *Regexp) MatchString(s string) bool { return r.Get().MatchString(s) }

// ReplaceAllString is regexp.Regexp.ReplaceAllString.
func (r *Regexp) ReplaceAllString(src, repl string) string {
	return r.Get().ReplaceAllString(src, repl)
}
