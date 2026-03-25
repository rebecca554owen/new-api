package middleware

import (
	"crypto/subtle"
	"net/http"
	"strings"

	"github.com/QuantumNous/new-api/constant"
	"github.com/gin-gonic/gin"
)

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
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
				"success": false,
				"message": "forbidden",
			})
			return
		}

		c.Next()
	}
}
