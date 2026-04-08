package auth

import (
	"net/http"
	"strings"

	"github.com/golang-jwt/jwt/v5"
)

// Middleware returns a chi middleware that validates IAM JWTs.
// It strips inbound identity headers, validates the Bearer token against the
// JWKS, and injects validated claims into the request context.
func Middleware(v *JWKSValidator) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Strip client-supplied identity headers (gateway does this too,
			// but defense in depth).
			r.Header.Del("X-Org-Id")
			r.Header.Del("X-User-Id")
			r.Header.Del("X-User-Email")

			authHeader := r.Header.Get("Authorization")
			if authHeader == "" {
				http.Error(w, `{"error":"missing authorization header"}`, http.StatusUnauthorized)
				return
			}

			tokenStr := strings.TrimPrefix(authHeader, "Bearer ")
			if tokenStr == authHeader {
				http.Error(w, `{"error":"invalid authorization scheme"}`, http.StatusUnauthorized)
				return
			}

			// Parse without validation first to get the kid.
			parser := jwt.NewParser(jwt.WithoutClaimsValidation())
			unverified, _, err := parser.ParseUnverified(tokenStr, jwt.MapClaims{})
			if err != nil {
				http.Error(w, `{"error":"malformed token"}`, http.StatusUnauthorized)
				return
			}

			kid, _ := unverified.Header["kid"].(string)
			if kid == "" {
				http.Error(w, `{"error":"token missing kid"}`, http.StatusUnauthorized)
				return
			}

			pubKey, err := v.GetKey(kid)
			if err != nil {
				http.Error(w, `{"error":"unknown signing key"}`, http.StatusUnauthorized)
				return
			}

			// Now verify the signature.
			token, err := jwt.Parse(tokenStr, func(t *jwt.Token) (any, error) {
				if _, ok := t.Method.(*jwt.SigningMethodRSA); !ok {
					return nil, jwt.ErrSignatureInvalid
				}
				return pubKey, nil
			})
			if err != nil || !token.Valid {
				http.Error(w, `{"error":"invalid token"}`, http.StatusUnauthorized)
				return
			}

			mapClaims, ok := token.Claims.(jwt.MapClaims)
			if !ok {
				http.Error(w, `{"error":"invalid claims"}`, http.StatusUnauthorized)
				return
			}

			claims := &Claims{
				Sub:   claimString(mapClaims, "sub"),
				Email: claimString(mapClaims, "email"),
				Owner: claimString(mapClaims, "owner"),
			}
			if roles, ok := mapClaims["roles"].([]any); ok {
				for _, r := range roles {
					if s, ok := r.(string); ok {
						claims.Roles = append(claims.Roles, s)
					}
				}
			}

			// Set identity headers for downstream use.
			r.Header.Set("X-Org-Id", claims.Owner)
			r.Header.Set("X-User-Id", claims.Sub)
			r.Header.Set("X-User-Email", claims.Email)

			ctx := WithClaims(r.Context(), claims)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func claimString(m jwt.MapClaims, key string) string {
	v, _ := m[key].(string)
	return v
}
