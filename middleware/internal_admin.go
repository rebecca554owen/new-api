package middleware

import (
	"bufio"
	"bytes"
	"crypto/subtle"
	"net"
	"net/http"
	"strings"

	"github.com/QuantumNous/new-api/constant"
	"github.com/gin-gonic/gin"
)

const internalAdminAuthPassedKey = "internal_admin_auth_passed"

type bufferedInternalAdminWriter struct {
	original gin.ResponseWriter
	header   http.Header
	body     bytes.Buffer
	size     int
	status   int
}

func newBufferedInternalAdminWriter(original gin.ResponseWriter) *bufferedInternalAdminWriter {
	return &bufferedInternalAdminWriter{
		original: original,
		header:   make(http.Header),
		size:     -1,
		status:   http.StatusOK,
	}
}

func (w *bufferedInternalAdminWriter) Header() http.Header {
	return w.header
}

func (w *bufferedInternalAdminWriter) WriteHeader(code int) {
	if code > 0 && !w.Written() {
		w.status = code
	}
}

func (w *bufferedInternalAdminWriter) WriteHeaderNow() {
	if !w.Written() {
		w.size = 0
	}
}

func (w *bufferedInternalAdminWriter) Write(data []byte) (int, error) {
	w.WriteHeaderNow()
	n, err := w.body.Write(data)
	w.size += n
	return n, err
}

func (w *bufferedInternalAdminWriter) WriteString(s string) (int, error) {
	w.WriteHeaderNow()
	n, err := w.body.WriteString(s)
	w.size += n
	return n, err
}

func (w *bufferedInternalAdminWriter) Status() int {
	return w.status
}

func (w *bufferedInternalAdminWriter) Size() int {
	return w.size
}

func (w *bufferedInternalAdminWriter) Written() bool {
	return w.size >= 0
}

func (w *bufferedInternalAdminWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	return w.original.Hijack()
}

func (w *bufferedInternalAdminWriter) CloseNotify() <-chan bool {
	return w.original.CloseNotify()
}

func (w *bufferedInternalAdminWriter) Flush() {}

func (w *bufferedInternalAdminWriter) Pusher() http.Pusher {
	return w.original.Pusher()
}

func (w *bufferedInternalAdminWriter) Forward(status int) {
	for key, values := range w.header {
		dst := w.original.Header()
		dst.Del(key)
		for _, value := range values {
			dst.Add(key, value)
		}
	}

	if status <= 0 {
		status = w.status
	}
	w.original.WriteHeader(status)
	if w.body.Len() > 0 {
		_, _ = w.original.Write(w.body.Bytes())
	}
}

func InternalAdminAuthStatus() gin.HandlerFunc {
	return func(c *gin.Context) {
		originalWriter := c.Writer
		bufferedWriter := newBufferedInternalAdminWriter(originalWriter)
		c.Writer = bufferedWriter

		c.Next()

		status := bufferedWriter.Status()
		if status == http.StatusOK {
			if _, authed := c.Get(internalAdminAuthPassedKey); !authed {
				status = http.StatusForbidden
			}
		}

		bufferedWriter.Forward(status)
	}
}

func MarkInternalAdminAuthPassed() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Set(internalAdminAuthPassedKey, true)
		c.Next()
	}
}

func InternalAdminSecretAuth() gin.HandlerFunc {
	return func(c *gin.Context) {
		expectedSecret := constant.InternalAdminSecret
		providedSecret := strings.TrimSpace(c.GetHeader("X-Internal-Admin-Secret"))

		if expectedSecret == "" {
			c.AbortWithStatusJSON(http.StatusServiceUnavailable, gin.H{
				"success": false,
				"message": "internal admin secret not configured",
			})
			return
		}

		if subtle.ConstantTimeCompare([]byte(providedSecret), []byte(expectedSecret)) != 1 {
			c.JSON(http.StatusForbidden, gin.H{
				"success": false,
				"message": "forbidden",
			})
			c.Abort()
			return
		}

		c.Next()
	}
}
