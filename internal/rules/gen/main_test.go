package main

import (
	"bytes"
	"os"
	"testing"
)

// TestGeneratedUpToDate fails when packs_gen.go no longer matches
// packs/*.yaml. Fix with `go generate ./internal/rules`.
func TestGeneratedUpToDate(t *testing.T) {
	want, err := Generate(os.DirFS(".."))
	if err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile("../packs_gen.go")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatal("internal/rules/packs_gen.go is stale; run `go generate ./internal/rules`")
	}
}
