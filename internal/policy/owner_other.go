//go:build !unix

package policy

import "os"

func ownedByMe(os.FileInfo) bool { return true }
