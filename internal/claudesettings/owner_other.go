//go:build !unix

package claudesettings

import "os"

func ownedByMe(os.FileInfo) bool { return true }
