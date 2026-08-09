// Package api wires the HTTP surface to the domain core: it renders the frozen
// error envelope, resolves identity fail-closed from the auth seam (never from
// browser-supplied headers), and implements the admission handlers over the
// repository, cooldown, pass-token, Space-seam, and LiveKit collaborators.
package api

import (
	"errors"

	"github.com/gin-gonic/gin"

	"github.com/Jerry-Xin/octo-meeting-service/internal/domain/merr"
)

const (
	requestIDHeader = "X-Request-Id"
	requestIDKey    = "request_id"
)

// RequestID middleware ensures every request has a correlation id, echoed on the
// response and available to handlers for error envelopes.
func RequestID() gin.HandlerFunc {
	return func(c *gin.Context) {
		rid := c.GetHeader(requestIDHeader)
		if rid == "" {
			rid = newRequestID()
		}
		c.Set(requestIDKey, rid)
		c.Writer.Header().Set(requestIDHeader, rid)
		c.Next()
	}
}

func requestIDOf(c *gin.Context) string {
	if v, ok := c.Get(requestIDKey); ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

// WriteError renders any error as the frozen envelope { code, message, details,
// request_id }. A non-merr error is mapped to MEETING_INTERNAL so no internal
// detail leaks. The HTTP status is taken from the code's catalog entry.
func WriteError(c *gin.Context, err error) {
	var me *merr.Error
	if !errors.As(err, &me) {
		me = merr.New(merr.Internal, "An unexpected error occurred.")
	}
	// Copy so we do not mutate a shared sentinel value.
	out := &merr.Error{Code: me.Code, Message: me.Message, Details: me.Details, RequestID: requestIDOf(c)}
	c.AbortWithStatusJSON(out.HTTPStatus(), out)
}

// WriteJSON renders a success payload with the request id echoed via header.
func WriteJSON(c *gin.Context, status int, body any) {
	c.JSON(status, body)
}
