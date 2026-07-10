package openai

import (
	"errors"
	"net/http/httptest"
	"testing"

	"github.com/QuantumNous/new-api/dto"
	"github.com/QuantumNous/new-api/model"
	relaycommon "github.com/QuantumNous/new-api/relay/common"
	"github.com/QuantumNous/new-api/types"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type recordingRealtimeBilling struct {
	initial int
	current int
	err     error
	targets []int
}

func (b *recordingRealtimeBilling) Settle(int) error                { return nil }
func (b *recordingRealtimeBilling) Refund(*gin.Context)             {}
func (b *recordingRealtimeBilling) NeedsRefund() bool               { return false }
func (b *recordingRealtimeBilling) GetPreConsumedQuota() int        { return b.current }
func (b *recordingRealtimeBilling) GetInitialPreConsumedQuota() int { return b.initial }
func (b *recordingRealtimeBilling) Reserve(target int) error {
	b.targets = append(b.targets, target)
	if b.err != nil {
		return b.err
	}
	if target > b.current {
		b.current = target
	}
	return nil
}

func realtimeBillingTestInfo(billing *recordingRealtimeBilling) *relaycommon.RelayInfo {
	return &relaycommon.RelayInfo{
		OriginModelName: "realtime-test",
		Billing:         billing,
		PriceData: types.PriceData{
			ModelRatio:           1,
			CompletionRatio:      1,
			AudioRatio:           1,
			AudioCompletionRatio: 1,
			GroupRatioInfo: types.GroupRatioInfo{
				GroupRatio: 1,
			},
		},
	}
}

func TestPreConsumeUsageCommitsCumulativeUsageOnlyAfterReserve(t *testing.T) {
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	billing := &recordingRealtimeBilling{initial: 10, current: 10}
	info := realtimeBillingTestInfo(billing)
	total := &dto.RealtimeUsage{
		TotalTokens:       5,
		InputTokens:       5,
		InputTokenDetails: dto.InputTokenDetails{TextTokens: 5},
	}
	chunk := &dto.RealtimeUsage{
		TotalTokens:       3,
		InputTokens:       3,
		InputTokenDetails: dto.InputTokenDetails{TextTokens: 3},
	}

	require.NoError(t, preConsumeUsage(c, info, chunk, total))
	assert.Equal(t, 8, total.TotalTokens)
	assert.Equal(t, 8, total.InputTokens)
	assert.Equal(t, 8, total.InputTokenDetails.TextTokens)
	assert.Equal(t, []int{18}, billing.targets)
	assert.Equal(t, 18, billing.current)
}

func TestPreConsumeUsageFailureStillRecordsDeliveredCumulativeUsage(t *testing.T) {
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	billing := &recordingRealtimeBilling{initial: 10, current: 10, err: model.ErrInsufficientUserQuota}
	info := realtimeBillingTestInfo(billing)
	total := &dto.RealtimeUsage{
		TotalTokens:       5,
		InputTokens:       5,
		InputTokenDetails: dto.InputTokenDetails{TextTokens: 5},
	}
	chunk := &dto.RealtimeUsage{
		TotalTokens:       3,
		InputTokens:       3,
		InputTokenDetails: dto.InputTokenDetails{TextTokens: 3},
	}

	err := preConsumeUsage(c, info, chunk, total)
	require.Error(t, err)
	assert.True(t, errors.Is(err, model.ErrInsufficientUserQuota))
	assert.Equal(t, 8, total.TotalTokens)
	assert.Equal(t, 8, total.InputTokens)
	assert.Equal(t, 8, total.InputTokenDetails.TextTokens)
	assert.Equal(t, []int{18}, billing.targets)
	assert.Equal(t, 10, billing.current)
}
