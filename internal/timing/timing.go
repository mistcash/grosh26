// Package timing holds tiny helpers shared between production commands and
// tests for reporting how long a step took.
package timing

import "time"

// Since returns how long has elapsed since start, rounded to the
// millisecond -- the resolution these packages log at.
func Since(start time.Time) time.Duration { return time.Since(start).Round(time.Millisecond) }
