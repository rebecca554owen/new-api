package service

import (
	"net/http"
	"testing"

	"github.com/QuantumNous/new-api/model"
	relaycommon "github.com/QuantumNous/new-api/relay/common"
	"github.com/QuantumNous/new-api/types"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAppendBillingInfoAddsStrictPreConsumeAudit(t *testing.T) {
	info := &relaycommon.RelayInfo{
		FinalPreConsumedQuota:      0,
		ActualQuota:                500,
		StrictPreConsume:           true,
		EffectiveMaxTokens:         8192,
		AtomicPreConsume:           true,
		AtomicPreConsumeDurationMs: 2,
		BillingReservationResult:   "settled",
		PriceData:                  types.PriceData{QuotaToPreConsume: 750},
	}
	other := map[string]interface{}{"admin_info": map[string]interface{}{}}

	appendBillingInfo(info, other)

	adminInfo, ok := other["admin_info"].(map[string]interface{})
	require.True(t, ok)
	assert.Equal(t, 0, adminInfo["pre_consumed_quota"])
	assert.Equal(t, 750, adminInfo["estimated_preconsume_quota"])
	assert.Equal(t, 500, adminInfo["actual_quota"])
	assert.Equal(t, 1.5, adminInfo["preconsume_ratio"])
	assert.Equal(t, 8192, adminInfo["effective_max_tokens"])
	assert.Equal(t, true, adminInfo["strict_preconsume"])
	assert.Equal(t, true, adminInfo["atomic_preconsume"])
	assert.Equal(t, int64(2), adminInfo["atomic_preconsume_duration_ms"])
	assert.Equal(t, "settled", adminInfo["billing_reservation_result"])
}

func TestAtomicQuotaUnavailableMapsToServiceUnavailable(t *testing.T) {
	apiErr := atomicQuotaAPIError(model.ErrAtomicQuotaUnavailable)
	assert.Equal(t, http.StatusServiceUnavailable, apiErr.StatusCode)
	assert.Equal(t, types.ErrorCodeBillingServiceUnavailable, apiErr.GetErrorCode())
}
