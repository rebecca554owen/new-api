package controller

import (
	"bytes"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/QuantumNous/new-api/common"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
)

const (
	testMaxSubscriptionCreemPayBodyBytes int64 = 4 << 10
	testMaxWalletCreemPayBodyBytes       int64 = 16 << 10
)

type creemCountingReader struct {
	reader io.Reader
	read   int64
}

func (r *creemCountingReader) Read(p []byte) (int, error) {
	n, err := r.reader.Read(p)
	r.read += int64(n)
	return n, err
}

type creemFiniteFillReader struct {
	remaining int64
	value     byte
}

func (r *creemFiniteFillReader) Read(p []byte) (int, error) {
	if r.remaining == 0 {
		return 0, io.EOF
	}
	if int64(len(p)) > r.remaining {
		p = p[:r.remaining]
	}
	for i := range p {
		p[i] = r.value
	}
	r.remaining -= int64(len(p))
	return len(p), nil
}

type creemErrorAfterReader struct {
	reader io.Reader
	err    error
}

func (r *creemErrorAfterReader) Read(p []byte) (int, error) {
	n, err := r.reader.Read(p)
	if err == io.EOF {
		return 0, r.err
	}
	return n, err
}

func creemPaddedJSONReader(jsonBody string, totalBytes int64) io.Reader {
	padding := totalBytes - int64(len(jsonBody))
	if padding < 0 {
		panic("JSON body exceeds requested fixture size")
	}
	return io.MultiReader(
		strings.NewReader(jsonBody),
		&creemFiniteFillReader{remaining: padding, value: ' '},
	)
}

func invokeCreemPayHandlerForTest(
	t *testing.T,
	handler gin.HandlerFunc,
	body io.Reader,
	contentLength int64,
) *httptest.ResponseRecorder {
	t.Helper()

	recorder := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(recorder)
	req := httptest.NewRequest(http.MethodPost, "/", body)
	req.Header.Set("Content-Type", gin.MIMEJSON)
	req.ContentLength = contentLength
	c.Request = req
	c.Set("id", 123)
	handler(c)
	return recorder
}

func creemResponseData(t *testing.T, recorder *httptest.ResponseRecorder) string {
	t.Helper()

	var payload map[string]any
	require.NoError(t, common.Unmarshal(recorder.Body.Bytes(), &payload))
	data, _ := payload["data"].(string)
	return data
}

func captureCreemInfoLogs(t *testing.T) *bytes.Buffer {
	t.Helper()

	var captured bytes.Buffer
	common.LogWriterMu.Lock()
	original := gin.DefaultWriter
	gin.DefaultWriter = &captured
	common.LogWriterMu.Unlock()
	t.Cleanup(func() {
		common.LogWriterMu.Lock()
		gin.DefaultWriter = original
		common.LogWriterMu.Unlock()
	})
	return &captured
}

func TestCreemPayHandlersRejectOversizedUnknownLengthBodies(t *testing.T) {
	testCases := []struct {
		name       string
		handler    gin.HandlerFunc
		body       string
		limitBytes int64
	}{
		{
			name:       "wallet top-up",
			handler:    RequestCreemPay,
			body:       `{"product_id":"product","payment_method":"unsupported"}`,
			limitBytes: testMaxWalletCreemPayBodyBytes,
		},
		{
			name:       "subscription purchase",
			handler:    SubscriptionRequestCreemPay,
			body:       `{"plan_id":0}`,
			limitBytes: testMaxSubscriptionCreemPayBodyBytes,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			body := &creemCountingReader{
				reader: creemPaddedJSONReader(tc.body, 2<<20),
			}
			recorder := invokeCreemPayHandlerForTest(t, tc.handler, body, -1)

			require.Equal(t, http.StatusRequestEntityTooLarge, recorder.Code)
			require.LessOrEqual(t, body.read, tc.limitBytes+1)
			require.Less(t, body.read, int64(2<<20), "the finite 2 MiB fixture must not be drained")
		})
	}
}

func TestCreemPayHandlersDoNotTrustUnderreportedContentLength(t *testing.T) {
	testCases := []struct {
		name       string
		handler    gin.HandlerFunc
		body       string
		limitBytes int64
	}{
		{
			name:       "wallet top-up",
			handler:    RequestCreemPay,
			body:       `{"product_id":"product","payment_method":"unsupported"}`,
			limitBytes: testMaxWalletCreemPayBodyBytes,
		},
		{
			name:       "subscription purchase",
			handler:    SubscriptionRequestCreemPay,
			body:       `{"plan_id":0}`,
			limitBytes: testMaxSubscriptionCreemPayBodyBytes,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			body := &creemCountingReader{
				reader: creemPaddedJSONReader(tc.body, tc.limitBytes+1),
			}
			recorder := invokeCreemPayHandlerForTest(t, tc.handler, body, tc.limitBytes-1)

			require.Equal(t, http.StatusRequestEntityTooLarge, recorder.Code)
			require.LessOrEqual(t, body.read, tc.limitBytes+1)
		})
	}
}

func TestCreemPayHandlersPreserveSmallBodyValidation(t *testing.T) {
	testCases := []struct {
		name         string
		handler      gin.HandlerFunc
		body         string
		totalBytes   int64
		expectedData string
	}{
		{
			name:         "wallet valid JSON reaches payment-method validation",
			handler:      RequestCreemPay,
			body:         `{"product_id":"product","payment_method":"unsupported"}`,
			totalBytes:   int64(len(`{"product_id":"product","payment_method":"unsupported"}`)),
			expectedData: "不支持的支付渠道",
		},
		{
			name:         "wallet malformed JSON",
			handler:      RequestCreemPay,
			body:         `{`,
			totalBytes:   1,
			expectedData: "参数错误",
		},
		{
			name:         "subscription valid JSON reaches plan validation",
			handler:      SubscriptionRequestCreemPay,
			body:         `{"plan_id":0}`,
			totalBytes:   int64(len(`{"plan_id":0}`)),
			expectedData: "参数错误",
		},
		{
			name:         "subscription malformed JSON",
			handler:      SubscriptionRequestCreemPay,
			body:         `{`,
			totalBytes:   1,
			expectedData: "参数错误",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			recorder := invokeCreemPayHandlerForTest(
				t,
				tc.handler,
				strings.NewReader(tc.body),
				tc.totalBytes,
			)

			require.Equal(t, http.StatusOK, recorder.Code)
			require.Equal(t, tc.expectedData, creemResponseData(t, recorder))
		})
	}
}

func TestCreemPayHandlersAcceptBodiesAtExactCeiling(t *testing.T) {
	testCases := []struct {
		name         string
		handler      gin.HandlerFunc
		body         string
		limitBytes   int64
		expectedData string
	}{
		{
			name:         "wallet top-up",
			handler:      RequestCreemPay,
			body:         `{"product_id":"product","payment_method":"unsupported"}`,
			limitBytes:   testMaxWalletCreemPayBodyBytes,
			expectedData: "不支持的支付渠道",
		},
		{
			name:         "subscription purchase",
			handler:      SubscriptionRequestCreemPay,
			body:         `{"plan_id":0}`,
			limitBytes:   testMaxSubscriptionCreemPayBodyBytes,
			expectedData: "参数错误",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			recorder := invokeCreemPayHandlerForTest(
				t,
				tc.handler,
				creemPaddedJSONReader(tc.body, tc.limitBytes),
				tc.limitBytes,
			)

			require.Equal(t, http.StatusOK, recorder.Code)
			require.Equal(t, tc.expectedData, creemResponseData(t, recorder))
		})
	}
}

func TestWalletCreemPayLogsMetadataWithoutRawBody(t *testing.T) {
	const bodyMarker = "never-log-this-product-marker"
	logs := captureCreemInfoLogs(t)

	recorder := invokeCreemPayHandlerForTest(
		t,
		RequestCreemPay,
		strings.NewReader(`{"product_id":"`+bodyMarker+`","payment_method":"unsupported"}`),
		-1,
	)

	require.Equal(t, http.StatusOK, recorder.Code)
	require.Contains(t, logs.String(), "user_id=123")
	require.NotContains(t, logs.String(), bodyMarker)
}

func TestCreemPayHandlersPreserveReadErrorResponse(t *testing.T) {
	testCases := []struct {
		name    string
		handler gin.HandlerFunc
	}{
		{name: "wallet top-up", handler: RequestCreemPay},
		{name: "subscription purchase", handler: SubscriptionRequestCreemPay},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			recorder := invokeCreemPayHandlerForTest(
				t,
				tc.handler,
				&creemErrorAfterReader{
					reader: strings.NewReader(`{"plan_id":`),
					err:    errors.New("synthetic read error"),
				},
				-1,
			)

			require.Equal(t, http.StatusOK, recorder.Code)
			require.Equal(t, "read query error", creemResponseData(t, recorder))
		})
	}
}
