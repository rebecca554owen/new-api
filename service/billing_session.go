package service

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/logger"
	"github.com/QuantumNous/new-api/model"
	relaycommon "github.com/QuantumNous/new-api/relay/common"
	"github.com/QuantumNous/new-api/types"

	"github.com/bytedance/gopkg/util/gopool"
	"github.com/gin-gonic/gin"
)

// ---------------------------------------------------------------------------
// BillingSession — 统一计费会话
// ---------------------------------------------------------------------------

// BillingSession 封装单次请求的预扣费/结算/退款生命周期。
// 实现 relaycommon.BillingSettler 接口。
type BillingSession struct {
	relayInfo        *relaycommon.RelayInfo
	funding          FundingSource
	preConsumedQuota int  // 实际预扣额度（信任用户可能为 0）
	tokenConsumed    int  // 令牌额度实际扣减量
	extraReserved    int  // 发送前补充预扣的额度（订阅退款时需要单独回滚）
	trusted          bool // 是否命中信任额度旁路
	dynamicTrust     *dynamicTrustReservation
	atomicQuota      *model.AtomicQuotaReservation
	fundingSettled   bool // funding.Settle 已成功，资金来源已提交
	settled          bool // Settle 全部完成（资金 + 令牌）
	refunded         bool // Refund 已调用
	mu               sync.Mutex
}

// Settle 根据实际消耗额度进行结算。
// 资金来源和令牌额度分两步提交：若资金来源已提交但令牌调整失败，
// 会标记 fundingSettled 防止 Refund 对已提交的资金来源执行退款。
func (s *BillingSession) Settle(actualQuota int) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.settled {
		return nil
	}
	s.relayInfo.ActualQuota = actualQuota
	if s.atomicQuota != nil {
		result, err := model.SettleAtomicQuota(s.atomicQuota, actualQuota)
		s.recordAtomicQuotaResult(result)
		if err != nil {
			return err
		}
		if actualQuota > s.preConsumedQuota {
			common.SysLog(fmt.Sprintf("strict pre-consume estimate exceeded (userId=%d, tokenId=%d, requestId=%s, actual=%d, preConsumed=%d)",
				s.relayInfo.UserId, s.relayInfo.TokenId, s.relayInfo.RequestId, actualQuota, s.preConsumedQuota))
		}
		s.fundingSettled = true
		s.settled = true
		return nil
	}
	delta := actualQuota - s.preConsumedQuota
	if delta == 0 {
		s.finalizeDynamicTrust(actualQuota)
		s.settled = true
		return nil
	}
	// 1) 调整资金来源（仅在尚未提交时执行，防止重复调用）
	if !s.fundingSettled {
		if err := s.funding.Settle(delta); err != nil {
			s.abandonDynamicTrust()
			return err
		}
		s.fundingSettled = true
	}
	// 2) 调整令牌额度
	var tokenErr error
	if !s.relayInfo.IsPlayground {
		if delta > 0 {
			tokenErr = model.DecreaseTokenQuota(s.relayInfo.TokenId, s.relayInfo.TokenKey, delta)
		} else {
			tokenErr = model.IncreaseTokenQuota(s.relayInfo.TokenId, s.relayInfo.TokenKey, -delta)
		}
		if tokenErr != nil {
			// 资金来源已提交，令牌调整失败只能记录日志；标记 settled 防止 Refund 误退资金
			common.SysLog(fmt.Sprintf("error adjusting token quota after funding settled (userId=%d, tokenId=%d, delta=%d): %s",
				s.relayInfo.UserId, s.relayInfo.TokenId, delta, tokenErr.Error()))
			s.abandonDynamicTrust()
		}
	}
	// 3) 更新 relayInfo 上的订阅 PostDelta（用于日志）
	if s.funding.Source() == BillingSourceSubscription {
		s.relayInfo.SubscriptionPostDelta += int64(delta)
	}
	if tokenErr == nil {
		s.finalizeDynamicTrust(actualQuota)
	}
	s.settled = true
	return tokenErr
}

func (s *BillingSession) finalizeDynamicTrust(actualQuota int) {
	if s.dynamicTrust == nil {
		return
	}
	s.dynamicTrust.stopHeartbeat()
	grace := time.Duration(common.BatchUpdateInterval+2) * time.Second
	if err := s.dynamicTrust.store.Settle(context.Background(), s.dynamicTrust, actualQuota, grace); err != nil {
		common.SysLog(fmt.Sprintf("failed to settle dynamic trust reservation (userId=%d, tokenId=%d, requestId=%s): %s",
			s.dynamicTrust.userID, s.dynamicTrust.tokenID, s.dynamicTrust.requestID, err.Error()))
	}
}

func (s *BillingSession) abandonDynamicTrust() {
	if s.dynamicTrust == nil {
		return
	}
	s.dynamicTrust.stopHeartbeat()
	if err := s.dynamicTrust.store.Release(context.Background(), s.dynamicTrust); err != nil {
		common.SysLog(fmt.Sprintf("failed to release dynamic trust reservation on abandon (userId=%d, tokenId=%d, requestId=%s): %s",
			s.dynamicTrust.userID, s.dynamicTrust.tokenID, s.dynamicTrust.requestID, err.Error()))
	}
}

// Refund 退还所有预扣费，幂等安全，异步执行。
func (s *BillingSession) Refund(c *gin.Context) {
	s.mu.Lock()
	if s.settled || s.refunded || !s.needsRefundLocked() {
		s.mu.Unlock()
		return
	}
	s.refunded = true
	dynamicTrust := s.dynamicTrust
	atomicQuota := s.atomicQuota
	if dynamicTrust != nil {
		dynamicTrust.stopHeartbeat()
	}
	s.mu.Unlock()
	if dynamicTrust != nil {
		if err := dynamicTrust.store.Release(context.Background(), dynamicTrust); err != nil {
			common.SysLog(fmt.Sprintf("failed to release dynamic trust reservation (userId=%d, tokenId=%d, requestId=%s): %s",
				dynamicTrust.userID, dynamicTrust.tokenID, dynamicTrust.requestID, err.Error()))
		}
	}
	if atomicQuota != nil {
		gopool.Go(func() {
			var lastErr error
			hadUnknownResult := false
			for attempt := 0; attempt < 3; attempt++ {
				result, err := model.RefundAtomicQuota(atomicQuota)
				if err == nil {
					if hadUnknownResult && result.AlreadyApplied {
						if recordErr := model.RecordAtomicQuotaRefund(atomicQuota); recordErr != nil {
							common.SysLog("error recording confirmed atomic quota refund: " + recordErr.Error())
						}
					}
					return
				}
				lastErr = err
				if !errors.Is(err, model.ErrAtomicQuotaUnavailable) {
					common.SysLog(fmt.Sprintf("atomic quota refund failed with non-retryable state (userId=%d, tokenId=%d, requestId=%s): %s",
						atomicQuota.UserID, atomicQuota.TokenID, atomicQuota.RequestID, err.Error()))
					return
				}
				hadUnknownResult = true
				if attempt < 2 {
					time.Sleep(time.Duration(50<<attempt) * time.Millisecond)
				}
			}
			common.SysLog(fmt.Sprintf("atomic quota refund exhausted retries, compensating batch records (userId=%d, tokenId=%d, requestId=%s): %s",
				atomicQuota.UserID, atomicQuota.TokenID, atomicQuota.RequestID, lastErr.Error()))
			if err := model.CompensateAtomicQuotaReservation(atomicQuota); err != nil {
				common.SysLog("error compensating atomic quota batch records: " + err.Error())
			}
		})
		return
	}

	logger.LogInfo(c, fmt.Sprintf("用户 %d 请求失败, 返还预扣费（token_quota=%s, funding=%s）",
		s.relayInfo.UserId,
		logger.FormatQuota(s.tokenConsumed),
		s.funding.Source(),
	))

	// 复制需要的值到闭包中
	tokenId := s.relayInfo.TokenId
	tokenKey := s.relayInfo.TokenKey
	isPlayground := s.relayInfo.IsPlayground
	tokenConsumed := s.tokenConsumed
	extraReserved := s.extraReserved
	subscriptionId := s.relayInfo.SubscriptionId
	funding := s.funding

	gopool.Go(func() {
		// 1) 退还资金来源
		if err := funding.Refund(); err != nil {
			common.SysLog("error refunding billing source: " + err.Error())
		}
		if extraReserved > 0 && funding.Source() == BillingSourceSubscription && subscriptionId > 0 {
			if err := model.PostConsumeUserSubscriptionDelta(subscriptionId, -int64(extraReserved)); err != nil {
				common.SysLog("error refunding subscription extra reserved quota: " + err.Error())
			}
		}
		// 2) 退还令牌额度
		if tokenConsumed > 0 && !isPlayground {
			if err := model.IncreaseTokenQuota(tokenId, tokenKey, tokenConsumed); err != nil {
				common.SysLog("error refunding token quota: " + err.Error())
			}
		}
	})
}

// NeedsRefund 返回是否存在需要退还的预扣状态。
func (s *BillingSession) NeedsRefund() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.needsRefundLocked()
}

func (s *BillingSession) needsRefundLocked() bool {
	if s.settled || s.refunded || s.fundingSettled {
		// fundingSettled 时资金来源已提交结算，不能再退预扣费
		return false
	}
	if s.tokenConsumed > 0 {
		return true
	}
	if s.dynamicTrust != nil {
		return true
	}
	if s.atomicQuota != nil {
		return true
	}
	// 订阅可能在 tokenConsumed=0 时仍预扣了额度
	if sub, ok := s.funding.(*SubscriptionFunding); ok && sub.preConsumed > 0 {
		return true
	}
	return false
}

// GetPreConsumedQuota 返回实际预扣的额度。
func (s *BillingSession) GetPreConsumedQuota() int {
	return s.preConsumedQuota
}

func (s *BillingSession) Reserve(targetQuota int) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.settled || s.refunded || targetQuota <= s.preConsumedQuota {
		return nil
	}
	if s.atomicQuota != nil {
		result, err := model.ResizeAtomicQuota(s.atomicQuota, targetQuota)
		s.recordAtomicQuotaResult(result)
		if err != nil {
			return err
		}
		delta := targetQuota - s.preConsumedQuota
		s.preConsumedQuota = targetQuota
		s.tokenConsumed += delta
		s.extraReserved += delta
		s.syncRelayInfo()
		return nil
	}
	if s.trusted {
		if s.dynamicTrust == nil || targetQuota <= s.dynamicTrust.amount {
			return nil
		}
		decision, err := s.dynamicTrust.store.Resize(context.Background(), s.dynamicTrust, targetQuota)
		if err == nil && decision.Trusted {
			return nil
		}
		if err != nil {
			common.SysLog(fmt.Sprintf("dynamic trust resize failed, falling back to pre-consume (userId=%d, tokenId=%d, requestId=%s): %s",
				s.dynamicTrust.userID, s.dynamicTrust.tokenID, s.dynamicTrust.requestID, err.Error()))
		} else {
			common.SysLog(fmt.Sprintf("dynamic trust threshold reached, falling back to pre-consume (userId=%d, tokenId=%d, requestId=%s, userThreshold=%s, tokenThreshold=%s)",
				s.dynamicTrust.userID, s.dynamicTrust.tokenID, s.dynamicTrust.requestID,
				logger.FormatQuota(decision.UserThreshold), logger.FormatQuota(decision.TokenThreshold)))
		}
		return s.preConsumeDynamicTrustFallback(targetQuota)
	}

	delta := targetQuota - s.preConsumedQuota
	if delta <= 0 {
		return nil
	}

	if err := s.reserveFunding(delta); err != nil {
		return err
	}
	if err := s.reserveToken(delta); err != nil {
		s.rollbackFundingReserve(delta)
		return err
	}

	s.preConsumedQuota += delta
	s.tokenConsumed += delta
	s.extraReserved += delta
	s.syncRelayInfo()
	return nil
}

// preConsumeDynamicTrustFallback converts an in-flight trusted request to the
// normal pre-consume path when Redis is unavailable or its threshold is hit.
func (s *BillingSession) preConsumeDynamicTrustFallback(targetQuota int) error {
	if common.PreConsumeAtomicEnabled && s.funding.Source() == BillingSourceWallet {
		if err := s.acquireAtomicQuota(targetQuota); err != nil {
			return err
		}
		reservation := s.dynamicTrust
		reservation.stopHeartbeat()
		s.trusted = false
		s.dynamicTrust = nil
		return nil
	}
	if wallet, ok := s.funding.(*WalletFunding); ok {
		userQuota, err := model.GetUserQuota(wallet.userId, false)
		if err != nil {
			return types.NewError(err, types.ErrorCodeQueryDataError, types.ErrOptionWithSkipRetry())
		}
		if userQuota < targetQuota {
			return types.NewErrorWithStatusCode(
				fmt.Errorf("用户额度不足, 剩余额度: %s, 需要预扣费额度: %s", logger.FormatQuota(userQuota), logger.FormatQuota(targetQuota)),
				types.ErrorCodeInsufficientUserQuota,
				http.StatusForbidden,
				types.ErrOptionWithSkipRetry(),
				types.ErrOptionWithNoRecordErrorLog(),
			)
		}
	}
	if err := s.funding.PreConsume(targetQuota); err != nil {
		return types.NewError(err, types.ErrorCodeUpdateDataError, types.ErrOptionWithSkipRetry())
	}
	if err := s.reserveToken(targetQuota); err != nil {
		s.rollbackFundingReserve(targetQuota)
		return err
	}

	reservation := s.dynamicTrust
	reservation.stopHeartbeat()
	s.preConsumedQuota = targetQuota
	s.tokenConsumed = targetQuota
	s.extraReserved += targetQuota
	s.trusted = false
	s.dynamicTrust = nil
	s.syncRelayInfo()

	if err := reservation.store.Release(context.Background(), reservation); err != nil {
		common.SysLog(fmt.Sprintf("failed to release dynamic trust reservation after pre-consume fallback (userId=%d, tokenId=%d, requestId=%s): %s",
			reservation.userID, reservation.tokenID, reservation.requestID, err.Error()))
	}
	return nil
}

// ---------------------------------------------------------------------------
// PreConsume — 统一预扣费入口（含信任额度旁路）
// ---------------------------------------------------------------------------

// preConsume 执行预扣费：信任检查 -> 令牌预扣 -> 资金来源预扣。
// 任一步骤失败时原子回滚已完成的步骤。
func (s *BillingSession) preConsume(c *gin.Context, quota int) *types.NewAPIError {
	effectiveQuota := quota

	// ---- 信任额度旁路 ----
	if s.shouldTrust(c, quota) {
		s.trusted = true
		effectiveQuota = 0
		logger.LogInfo(c, fmt.Sprintf("用户 %d 额度充足, 信任且不需要预扣费 (funding=%s)", s.relayInfo.UserId, s.funding.Source()))
	} else if effectiveQuota > 0 {
		logger.LogInfo(c, fmt.Sprintf("用户 %d 需要预扣费 %s (funding=%s)", s.relayInfo.UserId, logger.FormatQuota(effectiveQuota), s.funding.Source()))
	}
	if effectiveQuota > 0 && common.PreConsumeAtomicEnabled && s.funding.Source() == BillingSourceWallet {
		if err := s.acquireAtomicQuota(effectiveQuota); err != nil {
			return atomicQuotaAPIError(err)
		}
		return nil
	}

	// ---- 1) 预扣令牌额度 ----
	if effectiveQuota > 0 {
		if err := PreConsumeTokenQuota(s.relayInfo, effectiveQuota); err != nil {
			return types.NewErrorWithStatusCode(err, types.ErrorCodePreConsumeTokenQuotaFailed, http.StatusForbidden, types.ErrOptionWithSkipRetry(), types.ErrOptionWithNoRecordErrorLog())
		}
		s.tokenConsumed = effectiveQuota
	}

	// ---- 2) 预扣资金来源 ----
	if err := s.funding.PreConsume(effectiveQuota); err != nil {
		// 预扣费失败，回滚令牌额度
		if s.tokenConsumed > 0 && !s.relayInfo.IsPlayground {
			if rollbackErr := model.IncreaseTokenQuota(s.relayInfo.TokenId, s.relayInfo.TokenKey, s.tokenConsumed); rollbackErr != nil {
				common.SysLog(fmt.Sprintf("error rolling back token quota (userId=%d, tokenId=%d, amount=%d, fundingErr=%s): %s",
					s.relayInfo.UserId, s.relayInfo.TokenId, s.tokenConsumed, err.Error(), rollbackErr.Error()))
			}
			s.tokenConsumed = 0
		}
		// TODO: model 层应定义哨兵错误（如 ErrNoActiveSubscription），用 errors.Is 替代字符串匹配
		errMsg := err.Error()
		if strings.Contains(errMsg, "no active subscription") || strings.Contains(errMsg, "subscription quota insufficient") {
			return types.NewErrorWithStatusCode(fmt.Errorf("订阅额度不足或未配置订阅: %s", errMsg), types.ErrorCodeInsufficientUserQuota, http.StatusForbidden, types.ErrOptionWithSkipRetry(), types.ErrOptionWithNoRecordErrorLog())
		}
		return types.NewError(err, types.ErrorCodeUpdateDataError, types.ErrOptionWithSkipRetry())
	}

	s.preConsumedQuota = effectiveQuota

	// ---- 同步 RelayInfo 兼容字段 ----
	s.syncRelayInfo()

	return nil
}

func (s *BillingSession) acquireAtomicQuota(quota int) error {
	requestID := s.relayInfo.RequestId
	if requestID == "" {
		requestID = common.NewRequestId()
		s.relayInfo.RequestId = requestID
	}
	reservation := &model.AtomicQuotaReservation{
		RequestID:      requestID,
		UserID:         s.relayInfo.UserId,
		TokenID:        s.relayInfo.TokenId,
		TokenKey:       s.relayInfo.TokenKey,
		TokenUnlimited: s.relayInfo.TokenUnlimited || s.relayInfo.IsPlayground,
		Amount:         quota,
	}
	if s.dynamicTrust != nil {
		reservation.DynamicTrustRequestID = s.dynamicTrust.requestID
	}
	result, err := model.AcquireAtomicQuota(reservation)
	s.recordAtomicQuotaResult(result)
	s.relayInfo.AtomicPreConsumeDurationMs = result.Duration.Milliseconds()
	if err != nil {
		return err
	}
	s.atomicQuota = reservation
	s.preConsumedQuota = quota
	s.tokenConsumed = quota
	s.relayInfo.AtomicPreConsume = true
	s.syncRelayInfo()
	return nil
}

func (s *BillingSession) recordAtomicQuotaResult(result model.AtomicQuotaResult) {
	if s == nil || s.relayInfo == nil {
		return
	}
	if result.Status != "" {
		s.relayInfo.BillingReservationResult = result.Status
	}
}

func atomicQuotaAPIError(err error) *types.NewAPIError {
	switch {
	case errors.Is(err, model.ErrAtomicUserQuotaInsufficient):
		return types.NewErrorWithStatusCode(err, types.ErrorCodeInsufficientUserQuota, http.StatusForbidden,
			types.ErrOptionWithSkipRetry(), types.ErrOptionWithNoRecordErrorLog())
	case errors.Is(err, model.ErrAtomicTokenQuotaInsufficient):
		return types.NewErrorWithStatusCode(err, types.ErrorCodePreConsumeTokenQuotaFailed, http.StatusForbidden,
			types.ErrOptionWithSkipRetry(), types.ErrOptionWithNoRecordErrorLog())
	default:
		return types.NewErrorWithStatusCode(err, types.ErrorCodeBillingServiceUnavailable, http.StatusServiceUnavailable,
			types.ErrOptionWithSkipRetry())
	}
}

func (s *BillingSession) reserveFunding(delta int) error {
	switch funding := s.funding.(type) {
	case *WalletFunding:
		userQuota, err := model.GetUserQuota(funding.userId, false)
		if err != nil {
			return types.NewError(err, types.ErrorCodeQueryDataError, types.ErrOptionWithSkipRetry())
		}
		if userQuota < delta {
			return types.NewErrorWithStatusCode(
				fmt.Errorf("用户额度不足, 剩余额度: %s, 需要预扣费额度: %s", logger.FormatQuota(userQuota), logger.FormatQuota(delta)),
				types.ErrorCodeInsufficientUserQuota,
				http.StatusForbidden,
				types.ErrOptionWithSkipRetry(),
				types.ErrOptionWithNoRecordErrorLog(),
			)
		}
		if err := model.DecreaseUserQuota(funding.userId, delta, false); err != nil {
			return types.NewError(err, types.ErrorCodeUpdateDataError, types.ErrOptionWithSkipRetry())
		}
		funding.consumed += delta
		return nil
	case *SubscriptionFunding:
		if err := model.PostConsumeUserSubscriptionDelta(funding.subscriptionId, int64(delta)); err != nil {
			return types.NewErrorWithStatusCode(
				fmt.Errorf("订阅额度不足或未配置订阅: %s", err.Error()),
				types.ErrorCodeInsufficientUserQuota,
				http.StatusForbidden,
				types.ErrOptionWithSkipRetry(),
				types.ErrOptionWithNoRecordErrorLog(),
			)
		}
		return nil
	default:
		return types.NewError(fmt.Errorf("unsupported funding source: %s", s.funding.Source()), types.ErrorCodeUpdateDataError, types.ErrOptionWithSkipRetry())
	}
}

func (s *BillingSession) rollbackFundingReserve(delta int) {
	switch funding := s.funding.(type) {
	case *WalletFunding:
		if err := model.IncreaseUserQuota(funding.userId, delta, false); err != nil {
			common.SysLog("error rolling back wallet funding reserve: " + err.Error())
		} else {
			funding.consumed -= delta
		}
	case *SubscriptionFunding:
		if err := model.PostConsumeUserSubscriptionDelta(funding.subscriptionId, -int64(delta)); err != nil {
			common.SysLog("error rolling back subscription funding reserve: " + err.Error())
		}
	}
}

func (s *BillingSession) reserveToken(delta int) error {
	if delta <= 0 || s.relayInfo.IsPlayground {
		return nil
	}
	if err := PreConsumeTokenQuota(s.relayInfo, delta); err != nil {
		return types.NewErrorWithStatusCode(err, types.ErrorCodePreConsumeTokenQuotaFailed, http.StatusForbidden, types.ErrOptionWithSkipRetry(), types.ErrOptionWithNoRecordErrorLog())
	}
	return nil
}

// shouldTrust 统一信任额度检查，适用于钱包和订阅。
func (s *BillingSession) shouldTrust(c *gin.Context, quota int) bool {
	// 异步任务（ForcePreConsume=true）必须预扣全额，不允许信任旁路
	if s.relayInfo.ForcePreConsume || quota <= 0 || s.funding.Source() != BillingSourceWallet {
		return false
	}
	if common.PreConsumeAtomicEnabled && !common.TrustQuotaDynamicEnabled {
		return false
	}

	trustQuota := common.GetTrustQuota()
	if trustQuota <= 0 {
		return false
	}

	tokenQuota := c.GetInt("token_quota")
	if !common.TrustQuotaDynamicEnabled {
		if !s.relayInfo.TokenUnlimited && tokenQuota <= trustQuota {
			return false
		}
		return s.relayInfo.UserQuota > trustQuota
	}

	if !common.RedisEnabled || common.RDB == nil {
		return false
	}
	requestID := s.relayInfo.RequestId
	if requestID == "" {
		requestID = common.NewRequestId()
	}
	store := dynamicTrustStoreFactory()
	params := dynamicTrustAcquireParams{
		RequestID:      requestID,
		UserID:         s.relayInfo.UserId,
		TokenID:        s.relayInfo.TokenId,
		TokenKey:       s.relayInfo.TokenKey,
		Amount:         quota,
		TokenUnlimited: s.relayInfo.TokenUnlimited,
		MinQuota:       trustQuota,
		FactorMillis:   common.GetTrustQuotaDynamicFactorMillis(),
	}
	decision, err := store.Acquire(c.Request.Context(), params)
	if err != nil {
		logger.LogWarn(c, fmt.Sprintf("dynamic trust unavailable, falling back to pre-consume: %s", err.Error()))
		return false
	}
	if !decision.Trusted {
		logger.LogDebug(c, "dynamic trust denied: user_threshold=%d token_threshold=%d user_pending=%d token_pending=%d",
			decision.UserThreshold, decision.TokenThreshold, decision.UserPending, decision.TokenPending)
		return false
	}

	s.dynamicTrust = &dynamicTrustReservation{
		store:          store,
		requestID:      requestID,
		userID:         s.relayInfo.UserId,
		tokenID:        s.relayInfo.TokenId,
		tokenKey:       s.relayInfo.TokenKey,
		amount:         quota,
		tokenUnlimited: s.relayInfo.TokenUnlimited,
		minQuota:       trustQuota,
		factorMillis:   common.GetTrustQuotaDynamicFactorMillis(),
	}
	s.dynamicTrust.startHeartbeat()
	logger.LogDebug(c, "dynamic trust granted: user_threshold=%d token_threshold=%d user_pending=%d token_pending=%d",
		decision.UserThreshold, decision.TokenThreshold, decision.UserPending, decision.TokenPending)
	return true
}

// syncRelayInfo 将 BillingSession 的状态同步到 RelayInfo 的兼容字段上。
func (s *BillingSession) syncRelayInfo() {
	info := s.relayInfo
	info.FinalPreConsumedQuota = s.preConsumedQuota
	info.BillingSource = s.funding.Source()

	if sub, ok := s.funding.(*SubscriptionFunding); ok {
		info.SubscriptionId = sub.subscriptionId
		info.SubscriptionPreConsumed = sub.preConsumed + int64(s.extraReserved)
		info.SubscriptionPostDelta = 0
		info.SubscriptionAmountTotal = sub.AmountTotal
		info.SubscriptionAmountUsedAfterPreConsume = sub.AmountUsedAfter + int64(s.extraReserved)
		info.SubscriptionPlanId = sub.PlanId
		info.SubscriptionPlanTitle = sub.PlanTitle
	} else {
		info.SubscriptionId = 0
		info.SubscriptionPreConsumed = 0
	}
}

// ---------------------------------------------------------------------------
// NewBillingSession 工厂 — 根据计费偏好创建会话并处理回退
// ---------------------------------------------------------------------------

// NewBillingSession 根据用户计费偏好创建 BillingSession，处理 subscription_first / wallet_first 的回退。
func NewBillingSession(c *gin.Context, relayInfo *relaycommon.RelayInfo, preConsumedQuota int) (*BillingSession, *types.NewAPIError) {
	if relayInfo == nil {
		return nil, types.NewError(fmt.Errorf("relayInfo is nil"), types.ErrorCodeInvalidRequest, types.ErrOptionWithSkipRetry())
	}

	pref := common.NormalizeBillingPreference(relayInfo.UserSetting.BillingPreference)

	// 钱包路径需要先检查用户额度
	tryWallet := func() (*BillingSession, *types.NewAPIError) {
		userQuota, err := model.GetUserQuota(relayInfo.UserId, false)
		if err != nil {
			return nil, types.NewError(err, types.ErrorCodeQueryDataError, types.ErrOptionWithSkipRetry())
		}
		if !common.PreConsumeAtomicEnabled && userQuota <= 0 {
			return nil, types.NewErrorWithStatusCode(
				fmt.Errorf("用户额度不足, 剩余额度: %s", logger.FormatQuota(userQuota)),
				types.ErrorCodeInsufficientUserQuota, http.StatusForbidden,
				types.ErrOptionWithSkipRetry(), types.ErrOptionWithNoRecordErrorLog())
		}
		if !common.PreConsumeAtomicEnabled && userQuota-preConsumedQuota < 0 {
			return nil, types.NewErrorWithStatusCode(
				fmt.Errorf("预扣费额度失败, 用户剩余额度: %s, 需要预扣费额度: %s", logger.FormatQuota(userQuota), logger.FormatQuota(preConsumedQuota)),
				types.ErrorCodeInsufficientUserQuota, http.StatusForbidden,
				types.ErrOptionWithSkipRetry(), types.ErrOptionWithNoRecordErrorLog())
		}
		relayInfo.UserQuota = userQuota

		session := &BillingSession{
			relayInfo: relayInfo,
			funding:   &WalletFunding{userId: relayInfo.UserId},
		}
		if apiErr := session.preConsume(c, preConsumedQuota); apiErr != nil {
			return nil, apiErr
		}
		return session, nil
	}

	trySubscription := func() (*BillingSession, *types.NewAPIError) {
		subConsume := int64(preConsumedQuota)
		if subConsume <= 0 {
			subConsume = 1
		}
		session := &BillingSession{
			relayInfo: relayInfo,
			funding: &SubscriptionFunding{
				requestId: relayInfo.RequestId,
				userId:    relayInfo.UserId,
				modelName: relayInfo.OriginModelName,
				amount:    subConsume,
			},
		}
		// 必须传 subConsume 而非 preConsumedQuota，保证 SubscriptionFunding.amount、
		// preConsume 参数和 FinalPreConsumedQuota 三者一致，避免订阅多扣费。
		if apiErr := session.preConsume(c, int(subConsume)); apiErr != nil {
			return nil, apiErr
		}
		return session, nil
	}

	switch pref {
	case "subscription_only":
		return trySubscription()
	case "wallet_only":
		return tryWallet()
	case "wallet_first":
		session, err := tryWallet()
		if err != nil {
			if err.GetErrorCode() == types.ErrorCodeInsufficientUserQuota {
				return trySubscription()
			}
			return nil, err
		}
		return session, nil
	case "subscription_first":
		fallthrough
	default:
		hasSub, subCheckErr := model.HasActiveUserSubscription(relayInfo.UserId)
		if subCheckErr != nil {
			return nil, types.NewError(subCheckErr, types.ErrorCodeQueryDataError, types.ErrOptionWithSkipRetry())
		}
		if !hasSub {
			return tryWallet()
		}
		session, apiErr := trySubscription()
		if apiErr != nil {
			if apiErr.GetErrorCode() == types.ErrorCodeInsufficientUserQuota {
				// 仅当用户的活跃订阅允许钱包回退时才回退到钱包，否则返回订阅额度不足错误
				allowOverflow, overflowErr := model.UserActiveSubscriptionsAllowWalletOverflow(relayInfo.UserId)
				if overflowErr != nil {
					return nil, types.NewError(overflowErr, types.ErrorCodeQueryDataError, types.ErrOptionWithSkipRetry())
				}
				if allowOverflow {
					return tryWallet()
				}
				return nil, apiErr
			}
			return nil, apiErr
		}
		return session, nil
	}
}
