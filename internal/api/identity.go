package api

import (
	"crypto/rand"
	"encoding/hex"
	"strings"

	"github.com/gin-gonic/gin"

	"github.com/Jerry-Xin/octo-meeting-service/internal/domain/merr"
	"github.com/Jerry-Xin/octo-meeting-service/internal/seams"
)

const principalKey = "principal"

// newRequestID returns a random correlation id. crypto/rand is used so ids are
// unguessable; a failure falls back to a fixed marker rather than panicking.
func newRequestID() string {
	buf := make([]byte, 12)
	if _, err := rand.Read(buf); err != nil {
		return "req-unknown"
	}
	return hex.EncodeToString(buf)
}

// Identity resolves the caller's Principal from the auth seam and fails closed.
// It deliberately ignores any client-supplied x-user-id / x-org-id headers: the
// only trusted identity is what the auth seam returns for the verified
// credential. A missing or unverifiable credential yields MEETING_AUTH_REQUIRED.
func Identity(auth seams.Auth) gin.HandlerFunc {
	return func(c *gin.Context) {
		bearer := extractCredential(c)
		if bearer == "" {
			WriteError(c, merr.New(merr.AuthRequired, "Authentication is required."))
			return
		}
		p, err := auth.Authenticate(c.Request.Context(), bearer)
		if err != nil || p == nil || p.UserID == "" {
			WriteError(c, merr.New(merr.AuthRequired, "Authentication is required or the session has expired."))
			return
		}
		c.Set(principalKey, p)
		c.Next()
	}
}

// extractCredential reads the credential from the Octo `token` header, falling
// back to an Authorization: Bearer header. Browser identity headers are never
// consulted.
func extractCredential(c *gin.Context) string {
	if t := strings.TrimSpace(c.GetHeader("token")); t != "" {
		return t
	}
	auth := strings.TrimSpace(c.GetHeader("Authorization"))
	if strings.HasPrefix(auth, "Bearer ") {
		return strings.TrimSpace(strings.TrimPrefix(auth, "Bearer "))
	}
	return ""
}

// PrincipalOf returns the verified Principal set by Identity.
func PrincipalOf(c *gin.Context) (*seams.Principal, bool) {
	v, ok := c.Get(principalKey)
	if !ok {
		return nil, false
	}
	p, ok := v.(*seams.Principal)
	return p, ok
}
