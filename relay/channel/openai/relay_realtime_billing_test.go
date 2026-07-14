package openai

import (
	"testing"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/dto"
	relaycommon "github.com/QuantumNous/new-api/relay/common"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type recordingRealtimeBilling struct {
	targets []int
}

func (b *recordingRealtimeBilling) Settle(int) error { return nil }
func (b *recordingRealtimeBilling) Refund(*gin.Context) {
}
func (b *recordingRealtimeBilling) NeedsRefund() bool        { return false }
func (b *recordingRealtimeBilling) GetPreConsumedQuota() int { return 0 }
func (b *recordingRealtimeBilling) Reserve(targetQuota int) error {
	b.targets = append(b.targets, targetQuota)
	return nil
}

func TestPreConsumeUsageReservesCumulativeRealtimeQuota(t *testing.T) {
	oldDynamicEnabled := common.TrustQuotaDynamicEnabled
	common.TrustQuotaDynamicEnabled = true
	t.Cleanup(func() { common.TrustQuotaDynamicEnabled = oldDynamicEnabled })

	billing := &recordingRealtimeBilling{}
	info := &relaycommon.RelayInfo{
		OriginModelName: "gpt-4o-realtime-preview",
		UsingGroup:      "default",
		UserGroup:       "default",
		Billing:         billing,
	}
	ctx, _ := gin.CreateTestContext(nil)
	total := &dto.RealtimeUsage{}

	require.NoError(t, preConsumeUsage(ctx, info, &dto.RealtimeUsage{
		TotalTokens: 100,
		InputTokens: 100,
		InputTokenDetails: dto.InputTokenDetails{
			TextTokens: 100,
		},
	}, total))
	require.NoError(t, preConsumeUsage(ctx, info, &dto.RealtimeUsage{
		TotalTokens:  100,
		OutputTokens: 100,
		OutputTokenDetails: dto.OutputTokenDetails{
			TextTokens: 100,
		},
	}, total))

	require.Len(t, billing.targets, 2)
	assert.Positive(t, billing.targets[0])
	assert.Greater(t, billing.targets[1], billing.targets[0])
	assert.Equal(t, 200, total.TotalTokens)
}
