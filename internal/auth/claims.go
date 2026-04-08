// Package auth provides IAM JWT validation for the Hanzo KMS server.
package auth

import "context"

// Claims holds the validated fields from a Hanzo IAM JWT.
type Claims struct {
	Sub   string   `json:"sub"`
	Email string   `json:"email"`
	Owner string   `json:"owner"` // org slug
	Roles []string `json:"roles,omitempty"`
}

type ctxKey struct{}

// FromContext extracts validated claims from the request context.
func FromContext(ctx context.Context) *Claims {
	c, _ := ctx.Value(ctxKey{}).(*Claims)
	return c
}

// WithClaims stores validated claims in the context.
func WithClaims(ctx context.Context, c *Claims) context.Context {
	return context.WithValue(ctx, ctxKey{}, c)
}
