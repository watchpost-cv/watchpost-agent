//go:build windows

package telemetry

import "errors"

func filesystemPercent(string) (float64, error) {
	return 0, errors.New("filesystem collection is not yet implemented on Windows")
}
