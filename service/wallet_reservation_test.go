package service

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/dto"
	"github.com/QuantumNous/new-api/model"
	"github.com/QuantumNous/new-api/pkg/billingexpr"
	relaycommon "github.com/QuantumNous/new-api/relay/common"
	"github.com/QuantumNous/new-api/types"
	"github.com/gin-gonic/gin"
	"github.com/glebarez/sqlite"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

func setupWalletReservationBoundary(t *testing.T, userQuota int, tokenQuota int) (*gin.Context, *relaycommon.RelayInfo) {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(filepath.Join(t.TempDir(), "wallet-reservation.db")), &gorm.Config{})
	require.NoError(t, err)

	oldDB := model.DB
	oldLogDB := model.LOG_DB
	model.DB = db
	model.LOG_DB = db
	t.Cleanup(func() {
		model.DB = oldDB
		model.LOG_DB = oldLogDB
		if sqlDB, dbErr := db.DB(); dbErr == nil {
			_ = sqlDB.Close()
		}
	})
	require.NoError(t, db.AutoMigrate(
		&model.User{},
		&model.Token{},
		&model.SubscriptionPlan{},
		&model.UserSubscription{},
		&model.SubscriptionPreConsumeRecord{},
	))

	user := &model.User{
		Username: fmt.Sprintf("wallet-boundary-%d", time.Now().UnixNano()),
		Status:   common.UserStatusEnabled,
		Quota:    userQuota,
	}
	require.NoError(t, model.DB.Create(user).Error)
	token := &model.Token{
		UserId:         user.Id,
		Name:           "wallet-boundary-token",
		Key:            fmt.Sprintf("wallet-boundary-key-%d", time.Now().UnixNano()),
		Status:         common.TokenStatusEnabled,
		RemainQuota:    tokenQuota,
		UnlimitedQuota: false,
		ExpiredTime:    -1,
	}
	require.NoError(t, model.DB.Create(token).Error)

	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	return c, &relaycommon.RelayInfo{
		UserId:          user.Id,
		TokenId:         token.Id,
		TokenKey:        token.Key,
		ForcePreConsume: true,
	}
}

func persistedWalletAndTokenQuota(t *testing.T, info *relaycommon.RelayInfo) (int, int, int) {
	t.Helper()
	var user model.User
	var token model.Token
	require.NoError(t, model.DB.First(&user, info.UserId).Error)
	require.NoError(t, model.DB.First(&token, info.TokenId).Error)
	return user.Quota, token.RemainQuota, token.UsedQuota
}

func TestWalletPreConsumeAndSettlePreserveSingleRequestAccounting(t *testing.T) {
	c, info := setupWalletReservationBoundary(t, 100, 100)
	session := &BillingSession{
		relayInfo: info,
		funding:   &WalletFunding{userId: info.UserId},
	}

	require.Nil(t, session.preConsume(c, 60))
	userQuota, tokenRemain, tokenUsed := persistedWalletAndTokenQuota(t, info)
	assert.Equal(t, 40, userQuota)
	assert.Equal(t, 40, tokenRemain)
	assert.Equal(t, 60, tokenUsed)

	require.NoError(t, session.Settle(50))
	userQuota, tokenRemain, tokenUsed = persistedWalletAndTokenQuota(t, info)
	assert.Equal(t, 50, userQuota)
	assert.Equal(t, 50, tokenRemain)
	assert.Equal(t, 50, tokenUsed)
}

func TestWalletPositiveSettlementCannotOverdrawBalance(t *testing.T) {
	c, info := setupWalletReservationBoundary(t, 100, 200)
	session := &BillingSession{
		relayInfo: info,
		funding:   &WalletFunding{userId: info.UserId},
	}

	require.Nil(t, session.preConsume(c, 60))
	err := session.Settle(110)
	require.ErrorIs(t, err, model.ErrInsufficientUserQuota)

	userQuota, tokenRemain, tokenUsed := persistedWalletAndTokenQuota(t, info)
	assert.Equal(t, 40, userQuota)
	assert.Equal(t, 140, tokenRemain)
	assert.Equal(t, 60, tokenUsed)
	assert.GreaterOrEqual(t, userQuota, 0)
}

func TestPreWssConsumeQuotaReservesCumulativeUsageWithoutOverdraw(t *testing.T) {
	c, info := setupWalletReservationBoundary(t, 450, 1000)
	info.OriginModelName = "gpt-4o-realtime-preview"
	info.UsingGroup = "default"
	info.UserGroup = "default"
	info.UserSetting = dto.UserSetting{BillingPreference: "wallet_only"}
	info.PriceData = types.PriceData{
		ModelRatio:           2.5,
		CompletionRatio:      1,
		AudioRatio:           1,
		AudioCompletionRatio: 1,
		QuotaToPreConsume:    100,
		GroupRatioInfo: types.GroupRatioInfo{
			GroupRatio: 1,
		},
	}

	session, apiErr := NewBillingSession(c, info, 100)
	require.Nil(t, apiErr)
	require.NotNil(t, session)
	info.Billing = session

	firstUsage := &dto.RealtimeUsage{
		TotalTokens: 80,
		InputTokens: 80,
		InputTokenDetails: dto.InputTokenDetails{
			TextTokens: 80,
		},
	}
	require.NoError(t, PreWssConsumeQuota(c, info, firstUsage))
	assert.Equal(t, 300, session.GetPreConsumedQuota())
	userQuota, tokenRemain, tokenUsed := persistedWalletAndTokenQuota(t, info)
	assert.Equal(t, 150, userQuota)
	assert.Equal(t, 700, tokenRemain)
	assert.Equal(t, 300, tokenUsed)

	// Replaying the same cumulative snapshot must not reserve it twice.
	require.NoError(t, PreWssConsumeQuota(c, info, firstUsage))
	replayedUserQuota, replayedTokenRemain, replayedTokenUsed := persistedWalletAndTokenQuota(t, info)
	assert.Equal(t, userQuota, replayedUserQuota)
	assert.Equal(t, tokenRemain, replayedTokenRemain)
	assert.Equal(t, tokenUsed, replayedTokenUsed)
	assert.Equal(t, 300, session.GetPreConsumedQuota())

	secondUsage := &dto.RealtimeUsage{
		TotalTokens: 150,
		InputTokens: 150,
		InputTokenDetails: dto.InputTokenDetails{
			TextTokens: 150,
		},
	}
	err := PreWssConsumeQuota(c, info, secondUsage)
	require.Error(t, err)
	assert.True(t, errors.Is(err, model.ErrInsufficientUserQuota))

	userQuota, tokenRemain, tokenUsed = persistedWalletAndTokenQuota(t, info)
	assert.Equal(t, 150, userQuota)
	assert.Equal(t, 700, tokenRemain)
	assert.Equal(t, 300, tokenUsed)
	assert.Equal(t, 300, session.GetPreConsumedQuota())
	assert.GreaterOrEqual(t, userQuota, 0)
}

func TestPreWssConsumeQuotaKeepsHeadroomAndFinalSettlementChargesOnce(t *testing.T) {
	c, info := setupWalletReservationBoundary(t, 500, 1000)
	info.OriginModelName = "gpt-4o-realtime-preview"
	info.UserSetting = dto.UserSetting{BillingPreference: "wallet_only"}
	info.PriceData = types.PriceData{
		ModelRatio:           2.5,
		CompletionRatio:      1,
		AudioRatio:           1,
		AudioCompletionRatio: 1,
		QuotaToPreConsume:    100,
		GroupRatioInfo: types.GroupRatioInfo{
			GroupRatio: 1,
		},
	}

	session, apiErr := NewBillingSession(c, info, 100)
	require.Nil(t, apiErr)
	require.NotNil(t, session)
	info.Billing = session

	first := &dto.RealtimeUsage{
		TotalTokens: 80,
		InputTokens: 80,
		InputTokenDetails: dto.InputTokenDetails{
			TextTokens: 80,
		},
	}
	require.NoError(t, PreWssConsumeQuota(c, info, first))
	assert.Equal(t, 300, session.GetPreConsumedQuota())

	second := &dto.RealtimeUsage{
		TotalTokens: 120,
		InputTokens: 120,
		InputTokenDetails: dto.InputTokenDetails{
			TextTokens: 120,
		},
	}
	require.NoError(t, PreWssConsumeQuota(c, info, second))
	assert.Equal(t, 400, session.GetPreConsumedQuota())

	require.NoError(t, SettleBilling(c, info, 300))
	userQuota, tokenRemain, tokenUsed := persistedWalletAndTokenQuota(t, info)
	assert.Equal(t, 200, userQuota)
	assert.Equal(t, 700, tokenRemain)
	assert.Equal(t, 300, tokenUsed)
}

func TestPreWssConsumeQuotaFixedPriceDoesNotReserveTwice(t *testing.T) {
	c, info := setupWalletReservationBoundary(t, 100, 100)
	info.OriginModelName = "fixed-price-realtime"
	info.UserSetting = dto.UserSetting{BillingPreference: "wallet_only"}
	info.PriceData = types.PriceData{
		UsePrice:          true,
		ModelPrice:        1,
		QuotaToPreConsume: 100,
		GroupRatioInfo: types.GroupRatioInfo{
			GroupRatio: 1,
		},
	}

	session, apiErr := NewBillingSession(c, info, 100)
	require.Nil(t, apiErr)
	require.NotNil(t, session)
	info.Billing = session

	usage := &dto.RealtimeUsage{TotalTokens: 100, InputTokens: 100}
	require.NoError(t, PreWssConsumeQuota(c, info, usage))
	assert.Equal(t, 100, session.GetPreConsumedQuota())

	userQuota, tokenRemain, tokenUsed := persistedWalletAndTokenQuota(t, info)
	assert.Zero(t, userQuota)
	assert.Zero(t, tokenRemain)
	assert.Equal(t, 100, tokenUsed)
}

func TestRealtimeTieredParamsDriveWssReservationTarget(t *testing.T) {
	c, info := setupWalletReservationBoundary(t, 5000, 5000)
	info.OriginModelName = "tiered-realtime"
	info.UserSetting = dto.UserSetting{BillingPreference: "wallet_only"}
	info.PriceData = types.PriceData{QuotaToPreConsume: 100}

	const expr = "p + c + cr * 2 + ai * 3 + ao * 4"
	info.TieredBillingSnapshot = &billingexpr.BillingSnapshot{
		BillingMode:  "tiered_expr",
		ExprString:   expr,
		ExprHash:     billingexpr.ExprHashString(expr),
		GroupRatio:   1,
		QuotaPerUnit: 1_000_000,
		ExprVersion:  1,
	}

	session, apiErr := NewBillingSession(c, info, 100)
	require.Nil(t, apiErr)
	require.NotNil(t, session)
	info.Billing = session

	usage := &dto.RealtimeUsage{
		TotalTokens:  1500,
		InputTokens:  1000,
		OutputTokens: 500,
		InputTokenDetails: dto.InputTokenDetails{
			CachedTokens: 200,
			TextTokens:   700,
			AudioTokens:  100,
		},
		OutputTokenDetails: dto.OutputTokenDetails{
			TextTokens:  450,
			AudioTokens: 50,
		},
	}

	params := buildRealtimeTieredTokenParams(info, usage)
	assert.Equal(t, float64(700), params.P)
	assert.Equal(t, float64(450), params.C)
	assert.Equal(t, float64(1000), params.Len)
	assert.Equal(t, float64(200), params.CR)
	assert.Equal(t, float64(100), params.AI)
	assert.Equal(t, float64(50), params.AO)

	quota, clamp, _ := calculateWssQuota(info, usage)
	require.Nil(t, clamp)
	assert.Equal(t, 2050, quota)

	require.NoError(t, PreWssConsumeQuota(c, info, usage))
	assert.Equal(t, 2150, session.GetPreConsumedQuota())
	userQuota, tokenRemain, tokenUsed := persistedWalletAndTokenQuota(t, info)
	assert.Equal(t, 2850, userQuota)
	assert.Equal(t, 2850, tokenRemain)
	assert.Equal(t, 2150, tokenUsed)
}

func TestRealtimeTieredErrorFallbackIsStableAcrossReplay(t *testing.T) {
	c, info := setupWalletReservationBoundary(t, 500, 500)
	info.OriginModelName = "tiered-realtime-error"
	info.UserSetting = dto.UserSetting{BillingPreference: "wallet_only"}
	info.PriceData = types.PriceData{QuotaToPreConsume: 100}

	const invalidExpr = "invalid +-+ expr"
	info.TieredBillingSnapshot = &billingexpr.BillingSnapshot{
		BillingMode:              "tiered_expr",
		ExprString:               invalidExpr,
		ExprHash:                 billingexpr.ExprHashString(invalidExpr),
		GroupRatio:               1,
		EstimatedQuotaAfterGroup: 100,
		QuotaPerUnit:             1_000_000,
		ExprVersion:              1,
	}

	session, apiErr := NewBillingSession(c, info, 100)
	require.Nil(t, apiErr)
	require.NotNil(t, session)
	info.Billing = session

	usage := &dto.RealtimeUsage{TotalTokens: 100, InputTokens: 100}
	quota, clamp, result := calculateWssQuota(info, usage)
	assert.Equal(t, 100, quota)
	require.Nil(t, clamp)
	require.Nil(t, result)

	require.NoError(t, PreWssConsumeQuota(c, info, usage))
	assert.Equal(t, 200, session.GetPreConsumedQuota())
	require.NoError(t, PreWssConsumeQuota(c, info, usage))
	assert.Equal(t, 200, session.GetPreConsumedQuota(), "replaying the fallback snapshot must not grow the reservation")

	quota, _, _ = calculateWssQuota(info, usage)
	assert.Equal(t, 100, quota, "fallback actual quota must not follow the expanded reservation")
	require.NoError(t, SettleBilling(c, info, quota))
	userQuota, tokenRemain, tokenUsed := persistedWalletAndTokenQuota(t, info)
	assert.Equal(t, 400, userQuota)
	assert.Equal(t, 400, tokenRemain)
	assert.Equal(t, 100, tokenUsed)
}

func TestWssHeadroomFailureStillChargesDeliveredUsage(t *testing.T) {
	c, info := setupWalletReservationBoundary(t, 100, 100)
	info.OriginModelName = "realtime-headroom-failure"
	info.UserSetting = dto.UserSetting{BillingPreference: "wallet_only"}
	info.PriceData = types.PriceData{
		ModelRatio:           1,
		CompletionRatio:      1,
		AudioRatio:           1,
		AudioCompletionRatio: 1,
		QuotaToPreConsume:    100,
		GroupRatioInfo:       types.GroupRatioInfo{GroupRatio: 1},
	}

	session, apiErr := NewBillingSession(c, info, 100)
	require.Nil(t, apiErr)
	require.NotNil(t, session)
	info.Billing = session

	usage := &dto.RealtimeUsage{
		TotalTokens:       80,
		InputTokens:       80,
		InputTokenDetails: dto.InputTokenDetails{TextTokens: 80},
	}
	require.ErrorIs(t, PreWssConsumeQuota(c, info, usage), model.ErrInsufficientUserQuota)
	require.NoError(t, SettleBilling(c, info, 80))

	userQuota, tokenRemain, tokenUsed := persistedWalletAndTokenQuota(t, info)
	assert.Equal(t, 20, userQuota)
	assert.Equal(t, 20, tokenRemain)
	assert.Equal(t, 80, tokenUsed)
}

func TestWalletPreConsumeMapsInsufficientReservationAndRollsBackToken(t *testing.T) {
	c, info := setupWalletReservationBoundary(t, 40, 100)
	session := &BillingSession{
		relayInfo: info,
		funding:   &WalletFunding{userId: info.UserId},
	}

	apiErr := session.preConsume(c, 60)
	require.NotNil(t, apiErr)
	assert.Equal(t, types.ErrorCodeInsufficientUserQuota, apiErr.GetErrorCode())
	assert.Equal(t, http.StatusForbidden, apiErr.StatusCode)
	assert.True(t, errors.Is(apiErr, model.ErrInsufficientUserQuota))

	userQuota, tokenRemain, tokenUsed := persistedWalletAndTokenQuota(t, info)
	assert.Equal(t, 40, userQuota)
	assert.Equal(t, 100, tokenRemain)
	assert.Zero(t, tokenUsed)
}

func TestWalletReserveFundingMapsInsufficientReservation(t *testing.T) {
	_, info := setupWalletReservationBoundary(t, 40, 100)
	session := &BillingSession{
		relayInfo: info,
		funding:   &WalletFunding{userId: info.UserId},
	}

	err := session.reserveFunding(60)
	require.Error(t, err)
	var apiErr *types.NewAPIError
	require.True(t, errors.As(err, &apiErr))
	assert.Equal(t, types.ErrorCodeInsufficientUserQuota, apiErr.GetErrorCode())
	assert.Equal(t, http.StatusForbidden, apiErr.StatusCode)
	assert.True(t, errors.Is(err, model.ErrInsufficientUserQuota))
}

func TestHighBalanceWalletStillReservesBeforeDispatch(t *testing.T) {
	initialQuota := common.GetTrustQuota() + 100
	c, info := setupWalletReservationBoundary(t, initialQuota, 100)
	info.ForcePreConsume = false
	info.TokenUnlimited = true
	info.UserSetting = dto.UserSetting{BillingPreference: "wallet_only"}

	session, apiErr := NewBillingSession(c, info, 60)
	require.Nil(t, apiErr)
	require.NotNil(t, session)
	assert.Equal(t, 60, session.GetPreConsumedQuota())
	userQuota, tokenRemain, tokenUsed := persistedWalletAndTokenQuota(t, info)
	assert.Equal(t, initialQuota-60, userQuota)
	assert.Equal(t, 40, tokenRemain)
	assert.Equal(t, 60, tokenUsed)
}

func TestWalletFirstStillFallsBackToSubscription(t *testing.T) {
	c, info := setupWalletReservationBoundary(t, 0, 100)
	info.UserSetting = dto.UserSetting{BillingPreference: "wallet_first"}
	info.RequestId = fmt.Sprintf("wallet-fallback-%d", time.Now().UnixNano())
	info.OriginModelName = "wallet-fallback-model"

	plan := &model.SubscriptionPlan{
		Title:            "wallet fallback plan",
		DurationUnit:     model.SubscriptionDurationMonth,
		DurationValue:    1,
		TotalAmount:      100,
		QuotaResetPeriod: model.SubscriptionResetNever,
		Enabled:          true,
	}
	require.NoError(t, model.DB.Create(plan).Error)
	require.NoError(t, model.DB.Create(&model.UserSubscription{
		UserId:      info.UserId,
		PlanId:      plan.Id,
		AmountTotal: 100,
		AmountUsed:  0,
		StartTime:   time.Now().Add(-time.Hour).Unix(),
		EndTime:     time.Now().Add(time.Hour).Unix(),
		Status:      "active",
	}).Error)

	session, apiErr := NewBillingSession(c, info, 60)
	require.Nil(t, apiErr)
	require.NotNil(t, session)
	assert.Equal(t, BillingSourceSubscription, session.funding.Source())
	assert.Equal(t, BillingSourceSubscription, info.BillingSource)

	var subscription model.UserSubscription
	require.NoError(t, model.DB.Where("user_id = ?", info.UserId).First(&subscription).Error)
	assert.Equal(t, int64(60), subscription.AmountUsed)
	userQuota, tokenRemain, tokenUsed := persistedWalletAndTokenQuota(t, info)
	assert.Zero(t, userQuota)
	assert.Equal(t, 40, tokenRemain)
	assert.Equal(t, 60, tokenUsed)
}
