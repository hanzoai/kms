// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package metric

// Errs is a simple error accumulator used for collecting multiple errors
type Errs struct{ Err error }

// Errored returns true if any error has been added
func (errs *Errs) Errored() bool {
	return errs.Err != nil
}

// Add adds one or more errors to the accumulator
// Only the first non-nil error is kept
func (errs *Errs) Add(errors ...error) {
	if errs.Err == nil {
		for _, err := range errors {
			if err != nil {
				errs.Err = err
				break
			}
		}
	}
}
