// Copyright (C) 2019-2024, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package gomock

import (
	"testing"

	"go.uber.org/mock/gomock"
)

// NewController creates a new gomock.Controller
func NewController(t *testing.T) *gomock.Controller {
	return gomock.NewController(t)
}

// Controller is a re-export of gomock.Controller
type Controller = gomock.Controller

// Call is a re-export of gomock.Call
type Call = gomock.Call

// Matcher is a re-export of gomock.Matcher
type Matcher = gomock.Matcher

// Any returns a matcher that matches any value of the specified type
func Any() Matcher {
	return gomock.Any()
}

// Eq returns a matcher that matches values equal to x
func Eq(x interface{}) Matcher {
	return gomock.Eq(x)
}

// Not returns a matcher that negates the given matcher
func Not(m Matcher) Matcher {
	return gomock.Not(m)
}

// Nil returns a matcher that matches nil values
func Nil() Matcher {
	return gomock.Nil()
}