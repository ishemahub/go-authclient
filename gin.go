package authclient

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

// ctxClaimsKey is where validated claims are stored on the gin context.
const ctxClaimsKey = "authclient_claims"

// Authenticate is Gin middleware that validates the Bearer token and stores the
// claims on the context. Aborts with 401 if the token is missing or invalid.
//
//	r.Use(v.Authenticate())
func (v *Validator) Authenticate() gin.HandlerFunc {
	return func(c *gin.Context) {
		token, ok := BearerToken(c.GetHeader("Authorization"))
		if !ok {
			abort(c, http.StatusUnauthorized, "missing bearer token")
			return
		}
		claims, err := v.Validate(c.Request.Context(), token)
		if err != nil {
			abort(c, http.StatusUnauthorized, "invalid token")
			return
		}
		c.Set(ctxClaimsKey, claims)
		c.Next()
	}
}

// RequireRole ensures the authenticated principal holds the named role. Use
// after Authenticate().
//
//	g.GET("/things", v.Authenticate(), authclient.RequireRole("Admin"), handler)
func RequireRole(role string) gin.HandlerFunc {
	return func(c *gin.Context) {
		claims, ok := ClaimsFromContext(c)
		if !ok || !claims.HasRole(role) {
			abort(c, http.StatusForbidden, "missing required role: "+role)
			return
		}
		c.Next()
	}
}

// RequirePermission ensures the principal holds the named permission. Use after
// Authenticate().
func RequirePermission(perm string) gin.HandlerFunc {
	return func(c *gin.Context) {
		claims, ok := ClaimsFromContext(c)
		if !ok || !claims.HasPermission(perm) {
			abort(c, http.StatusForbidden, "missing required permission: "+perm)
			return
		}
		c.Next()
	}
}

// ClaimsFromContext returns the validated claims set by Authenticate().
func ClaimsFromContext(c *gin.Context) (*Claims, bool) {
	v, ok := c.Get(ctxClaimsKey)
	if !ok {
		return nil, false
	}
	claims, ok := v.(*Claims)
	return claims, ok
}

func abort(c *gin.Context, status int, msg string) {
	c.AbortWithStatusJSON(status, gin.H{"error": msg})
}
