package lazyre

import (
	"sync"
	"testing"
)

var pkgRe = Regexp{Expr: `^[a-z]+(-[a-z]+)*$`}

func TestCompilesOnFirstUse(t *testing.T) {
	r := &Regexp{Expr: `a+`}
	if r.re != nil {
		t.Fatal("compiled before first use")
	}
	if !r.MatchString("baab") || r.MatchString("bcd") {
		t.Fatal("MatchString wrong")
	}
	first := r.Get()
	if r.Get() != first {
		t.Fatal("recompiled on second use")
	}
	if got := r.ReplaceAllString("xaay", "-"); got != "x-y" {
		t.Fatalf("ReplaceAllString = %q", got)
	}
}

func TestPackageLevelConcurrent(t *testing.T) {
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if !pkgRe.MatchString("ab-cd") || pkgRe.MatchString("ab--cd") {
				t.Error("MatchString wrong")
			}
		}()
	}
	wg.Wait()
}

func TestInvalidPanicsAtFirstUse(t *testing.T) {
	r := &Regexp{Expr: `(`}
	for i := 0; i < 2; i++ { // the second call must panic too, not return nil
		func() {
			defer func() {
				if recover() == nil {
					t.Fatalf("call %d: no panic for an invalid expression", i+1)
				}
			}()
			r.Get()
		}()
	}
}
