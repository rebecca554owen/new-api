package helper

import (
	"testing"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/dto"
	relaycommon "github.com/QuantumNous/new-api/relay/common"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestApplyStrictPreConsumeLimitUsesDefaultForSupportedRequests(t *testing.T) {
	oldEnabled := common.PreConsumeStrictEnabled
	oldDefault := common.PreConsumeDefaultMaxTokens
	common.PreConsumeStrictEnabled = true
	common.PreConsumeDefaultMaxTokens = 8192
	t.Cleanup(func() {
		common.PreConsumeStrictEnabled = oldEnabled
		common.PreConsumeDefaultMaxTokens = oldDefault
	})

	tests := []struct {
		name    string
		request dto.Request
		get     func(dto.Request) uint
	}{
		{
			name:    "openai chat",
			request: &dto.GeneralOpenAIRequest{},
			get: func(request dto.Request) uint {
				return *request.(*dto.GeneralOpenAIRequest).MaxTokens
			},
		},
		{
			name:    "openai responses",
			request: &dto.OpenAIResponsesRequest{},
			get: func(request dto.Request) uint {
				return *request.(*dto.OpenAIResponsesRequest).MaxOutputTokens
			},
		},
		{
			name:    "claude",
			request: &dto.ClaudeRequest{},
			get: func(request dto.Request) uint {
				return *request.(*dto.ClaudeRequest).MaxTokens
			},
		},
		{
			name:    "gemini",
			request: &dto.GeminiChatRequest{},
			get: func(request dto.Request) uint {
				return *request.(*dto.GeminiChatRequest).GenerationConfig.MaxOutputTokens
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			info := &relaycommon.RelayInfo{OriginModelName: "strict-ratio-model", Request: test.request}
			ApplyStrictPreConsumeLimit(info)
			require.True(t, info.StrictPreConsume)
			assert.EqualValues(t, 8192, test.get(test.request))
			assert.Equal(t, 8192, info.EffectiveMaxTokens)
		})
	}
}

func TestApplyStrictPreConsumeLimitPreservesExplicitMaximum(t *testing.T) {
	oldEnabled := common.PreConsumeStrictEnabled
	common.PreConsumeStrictEnabled = true
	t.Cleanup(func() { common.PreConsumeStrictEnabled = oldEnabled })

	maxTokens := uint(2048)
	maxCompletionTokens := uint(4096)
	request := &dto.GeneralOpenAIRequest{
		MaxTokens:           &maxTokens,
		MaxCompletionTokens: &maxCompletionTokens,
	}
	info := &relaycommon.RelayInfo{OriginModelName: "strict-ratio-model", Request: request}

	ApplyStrictPreConsumeLimit(info)

	assert.EqualValues(t, 2048, *request.MaxTokens)
	assert.EqualValues(t, 4096, *request.MaxCompletionTokens)
	assert.Equal(t, 4096, info.EffectiveMaxTokens)
}
