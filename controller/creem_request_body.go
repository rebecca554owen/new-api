package controller

import (
	"bytes"
	"io"
	"net/http"

	"github.com/gin-gonic/gin"
)

const (
	maxSubscriptionCreemPayRequestBodyBytes int64 = 4 << 10
	maxWalletCreemPayRequestBodyBytes       int64 = 16 << 10
)

func readCreemPayRequestBody(c *gin.Context, maxBytes int64) error {
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, maxBytes)
	bodyBytes, err := io.ReadAll(c.Request.Body)
	if err != nil {
		return err
	}

	c.Request.Body = io.NopCloser(bytes.NewReader(bodyBytes))
	c.Request.ContentLength = int64(len(bodyBytes))
	return nil
}
