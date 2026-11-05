//go:build !unix

package uistate

import "errors"

func spawn(string, []string, []string) (int, error) {
	return 0, errors.New("uistate: background start needs macOS or Linux")
}
