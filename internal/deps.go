// Package internal pins the module's dependencies until the packages that use them land.
package internal

import (
	_ "github.com/bmatcuk/doublestar/v4"
	_ "github.com/goccy/go-yaml"
	_ "mvdan.cc/sh/v3/syntax"
)
