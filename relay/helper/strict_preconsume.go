package helper

import (
	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/dto"
	relaycommon "github.com/QuantumNous/new-api/relay/common"
	"github.com/QuantumNous/new-api/setting/billing_setting"
	"github.com/QuantumNous/new-api/setting/ratio_setting"
)

func ApplyStrictPreConsumeLimit(info *relaycommon.RelayInfo) {
	if info == nil || info.Request == nil || !common.PreConsumeStrictEnabled {
		return
	}
	if billing_setting.GetBillingMode(info.OriginModelName) != billing_setting.BillingModeTieredExpr {
		if _, usePrice := ratio_setting.GetModelPrice(info.OriginModelName, false); usePrice {
			return
		}
	}

	defaultMaxTokens := uint(common.PreConsumeDefaultMaxTokens)
	effectiveMaxTokens := uint(0)
	switch request := info.Request.(type) {
	case *dto.GeneralOpenAIRequest:
		if request.MaxTokens != nil {
			effectiveMaxTokens = *request.MaxTokens
		}
		if request.MaxCompletionTokens != nil && *request.MaxCompletionTokens > effectiveMaxTokens {
			effectiveMaxTokens = *request.MaxCompletionTokens
		}
		if effectiveMaxTokens == 0 {
			request.MaxTokens = &defaultMaxTokens
			effectiveMaxTokens = defaultMaxTokens
		}
	case *dto.OpenAIResponsesRequest:
		if request.MaxOutputTokens != nil {
			effectiveMaxTokens = *request.MaxOutputTokens
		}
		if effectiveMaxTokens == 0 {
			request.MaxOutputTokens = &defaultMaxTokens
			effectiveMaxTokens = defaultMaxTokens
		}
	case *dto.ClaudeRequest:
		if request.MaxTokens != nil {
			effectiveMaxTokens = *request.MaxTokens
		}
		if request.MaxTokensToSample != nil && *request.MaxTokensToSample > effectiveMaxTokens {
			effectiveMaxTokens = *request.MaxTokensToSample
		}
		if effectiveMaxTokens == 0 {
			request.MaxTokens = &defaultMaxTokens
			effectiveMaxTokens = defaultMaxTokens
		}
	case *dto.GeminiChatRequest:
		if request.GenerationConfig.MaxOutputTokens != nil {
			effectiveMaxTokens = *request.GenerationConfig.MaxOutputTokens
		}
		if effectiveMaxTokens == 0 {
			request.GenerationConfig.MaxOutputTokens = &defaultMaxTokens
			effectiveMaxTokens = defaultMaxTokens
		}
	default:
		return
	}

	info.StrictPreConsume = true
	info.EffectiveMaxTokens = int(effectiveMaxTokens)
}
