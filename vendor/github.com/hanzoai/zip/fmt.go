package zip

import "fmt"

// sprintf isolates the fmt import to one file for hot-path swapping.
func sprintf(format string, args ...any) string {
	if len(args) == 0 {
		return format
	}
	return fmt.Sprintf(format, args...)
}
