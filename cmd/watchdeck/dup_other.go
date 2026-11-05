//go:build !darwin && !linux

package main

import "errors"

const oNoFollow = 0

func dupTo(int, int) error { return errors.New("not supported here") }
