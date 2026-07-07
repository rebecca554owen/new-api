package vertex

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/QuantumNous/new-api/dto"
	relaycommon "github.com/QuantumNous/new-api/relay/common"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
)

func TestConvertOpenAIRequestRejectsHugeImagenNFromExtraBody(t *testing.T) {
	gin.SetMode(gin.TestMode)
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	c.Request = httptest.NewRequest(http.MethodPost, "/v1/chat/completions", nil)

	adaptor := &Adaptor{RequestMode: RequestModeGemini}
	info := &relaycommon.RelayInfo{
		ChannelMeta: &relaycommon.ChannelMeta{UpstreamModelName: "imagen-3.0-generate-001"},
	}
	req := &dto.GeneralOpenAIRequest{
		Model:     "imagen-3.0-generate-001",
		Prompt:    "draw",
		ExtraBody: json.RawMessage(`{"n":129}`),
	}

	_, err := adaptor.ConvertOpenAIRequest(c, info, req)
	require.ErrorContains(t, err, "n must be")
}
