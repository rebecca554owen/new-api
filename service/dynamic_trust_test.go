package service

import (
	"context"
	"errors"
	"fmt"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/QuantumNous/new-api/common"
	relaycommon "github.com/QuantumNous/new-api/relay/common"

	"github.com/alicebob/miniredis/v2"
	"github.com/gin-gonic/gin"
	"github.com/go-redis/redis/v8"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type fakeDynamicTrustStore struct {
	mu             sync.Mutex
	decision       dynamicTrustDecision
	acquireErr     error
	resizeDecision dynamicTrustDecision
	resizeErr      error
	acquireCalls   int
	resizeCalls    int
	refreshCalls   int
	settleCalls    int
	releaseCalls   int
	settledQuota   int
}

func (s *fakeDynamicTrustStore) Acquire(_ context.Context, _ dynamicTrustAcquireParams) (dynamicTrustDecision, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.acquireCalls++
	return s.decision, s.acquireErr
}

func (s *fakeDynamicTrustStore) Resize(_ context.Context, reservation *dynamicTrustReservation, targetQuota int) (dynamicTrustDecision, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.resizeCalls++
	if s.resizeErr == nil && s.resizeDecision.Trusted {
		reservation.amount = targetQuota
	}
	return s.resizeDecision, s.resizeErr
}

func (s *fakeDynamicTrustStore) Refresh(_ context.Context, _ *dynamicTrustReservation) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.refreshCalls++
	return nil
}

func (s *fakeDynamicTrustStore) Settle(_ context.Context, _ *dynamicTrustReservation, actualQuota int, _ time.Duration) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.settleCalls++
	s.settledQuota = actualQuota
	return nil
}

func (s *fakeDynamicTrustStore) Release(_ context.Context, _ *dynamicTrustReservation) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.releaseCalls++
	return nil
}

type fakeWalletFunding struct {
	settledDelta int
	preConsumed  int
}

func (f *fakeWalletFunding) Source() string { return BillingSourceWallet }
func (f *fakeWalletFunding) PreConsume(quota int) error {
	f.preConsumed += quota
	return nil
}
func (f *fakeWalletFunding) Settle(delta int) error {
	f.settledDelta += delta
	return nil
}
func (f *fakeWalletFunding) Refund() error { return nil }

func setupDynamicTrustTest(t *testing.T, store *fakeDynamicTrustStore) (*gin.Context, *BillingSession) {
	t.Helper()
	gin.SetMode(gin.TestMode)
	c, _ := gin.CreateTestContext(nil)
	c.Request = httptest.NewRequest("POST", "/v1/chat/completions", nil)
	c.Set("token_quota", 100_000_000)

	oldEnabled := common.TrustQuotaDynamicEnabled
	oldMinUSD := common.TrustQuotaMinUSD
	oldFactor := common.TrustQuotaDynamicFactor
	oldRedisEnabled := common.RedisEnabled
	oldRDB := common.RDB
	oldFactory := dynamicTrustStoreFactory
	common.TrustQuotaDynamicEnabled = true
	common.TrustQuotaMinUSD = 10
	common.TrustQuotaDynamicFactor = 1.5
	common.RedisEnabled = true
	testRDB := redis.NewClient(&redis.Options{Addr: "127.0.0.1:0"})
	common.RDB = testRDB
	dynamicTrustStoreFactory = func() dynamicTrustStore { return store }
	t.Cleanup(func() {
		_ = testRDB.Close()
		common.TrustQuotaDynamicEnabled = oldEnabled
		common.TrustQuotaMinUSD = oldMinUSD
		common.TrustQuotaDynamicFactor = oldFactor
		common.RedisEnabled = oldRedisEnabled
		common.RDB = oldRDB
		dynamicTrustStoreFactory = oldFactory
	})

	info := &relaycommon.RelayInfo{
		RequestId:      "request-dynamic-trust",
		UserId:         101,
		TokenId:        201,
		UserQuota:      100_000_000,
		TokenUnlimited: true,
		IsPlayground:   true,
	}
	session := &BillingSession{relayInfo: info, funding: &fakeWalletFunding{}}
	return c, session
}

func TestDynamicTrustReservationSettlesActualQuota(t *testing.T) {
	store := &fakeDynamicTrustStore{decision: dynamicTrustDecision{Trusted: true, UserThreshold: 6_000_000}}
	c, session := setupDynamicTrustTest(t, store)

	// Exercise the lifecycle directly after a successful dynamic decision.
	reservation := &dynamicTrustReservation{
		store: store, requestID: "request-dynamic-trust", userID: 101, tokenID: 201, amount: 1_000,
	}
	session.dynamicTrust = reservation
	session.trusted = true
	reservation.startHeartbeat()

	require.NoError(t, session.Settle(1_500))
	assert.Equal(t, 1_500, session.funding.(*fakeWalletFunding).settledDelta)
	assert.Equal(t, 1, store.settleCalls)
	assert.Equal(t, 1_500, store.settledQuota)
	assert.False(t, session.NeedsRefund())
	_ = c
}

func TestDynamicTrustDecisionRegistersReservation(t *testing.T) {
	store := &fakeDynamicTrustStore{decision: dynamicTrustDecision{
		Trusted: true, UserThreshold: 6_000_000, UserPending: 2_000_000,
	}}
	c, session := setupDynamicTrustTest(t, store)

	assert.True(t, session.shouldTrust(c, 1_000_000))
	require.NotNil(t, session.dynamicTrust)
	assert.Equal(t, 1_000_000, session.dynamicTrust.amount)
	assert.Equal(t, 1, store.acquireCalls)
	session.dynamicTrust.stopHeartbeat()
}

func TestDynamicTrustDecisionFallsBackWhenDenied(t *testing.T) {
	store := &fakeDynamicTrustStore{decision: dynamicTrustDecision{
		Trusted: false, UserThreshold: 100_000_000, UserPending: 80_000_000,
	}}
	c, session := setupDynamicTrustTest(t, store)

	assert.False(t, session.shouldTrust(c, 1_000_000))
	assert.Nil(t, session.dynamicTrust)
	assert.Equal(t, 1, store.acquireCalls)
}

func TestDynamicTrustDecisionFallsBackWhenRedisFails(t *testing.T) {
	store := &fakeDynamicTrustStore{acquireErr: errors.New("redis timeout")}
	c, session := setupDynamicTrustTest(t, store)

	assert.False(t, session.shouldTrust(c, 1_000_000))
	assert.Nil(t, session.dynamicTrust)
	assert.Equal(t, 1, store.acquireCalls)
}

func TestDynamicTrustSkipsForcedPreConsume(t *testing.T) {
	store := &fakeDynamicTrustStore{decision: dynamicTrustDecision{Trusted: true}}
	c, session := setupDynamicTrustTest(t, store)
	session.relayInfo.ForcePreConsume = true

	assert.False(t, session.shouldTrust(c, 1_000_000))
	assert.Zero(t, store.acquireCalls)
}

func TestAtomicPreConsumeDisablesStaticTrustBypass(t *testing.T) {
	store := &fakeDynamicTrustStore{decision: dynamicTrustDecision{Trusted: true}}
	c, session := setupDynamicTrustTest(t, store)
	oldAtomic := common.PreConsumeAtomicEnabled
	common.PreConsumeAtomicEnabled = true
	common.TrustQuotaDynamicEnabled = false
	t.Cleanup(func() { common.PreConsumeAtomicEnabled = oldAtomic })

	assert.False(t, session.shouldTrust(c, 1_000_000))
	assert.Zero(t, store.acquireCalls)
}

func TestDynamicTrustReservationRefundReleasesOnce(t *testing.T) {
	store := &fakeDynamicTrustStore{}
	c, session := setupDynamicTrustTest(t, store)
	reservation := &dynamicTrustReservation{
		store: store, requestID: "request-dynamic-trust", userID: 101, tokenID: 201, amount: 1_000,
	}
	session.dynamicTrust = reservation
	session.trusted = true
	reservation.startHeartbeat()

	assert.True(t, session.NeedsRefund())
	session.Refund(c)
	session.Refund(c)
	assert.Equal(t, 1, store.releaseCalls)
	assert.False(t, session.NeedsRefund())
}

func TestDynamicTrustReservationResize(t *testing.T) {
	store := &fakeDynamicTrustStore{resizeDecision: dynamicTrustDecision{Trusted: true, UserThreshold: 8_000_000}}
	_, session := setupDynamicTrustTest(t, store)
	session.trusted = true
	session.dynamicTrust = &dynamicTrustReservation{
		store: store, requestID: "request-dynamic-trust", userID: 101, tokenID: 201, amount: 1_000,
	}

	require.NoError(t, session.Reserve(2_000))
	assert.Equal(t, 1, store.resizeCalls)
	assert.Equal(t, 2_000, session.dynamicTrust.amount)

	require.NoError(t, session.Reserve(1_500))
	assert.Equal(t, 1, store.resizeCalls)
}

func TestDynamicTrustResizeFallsBackToPreConsume(t *testing.T) {
	testCases := []struct {
		name  string
		store *fakeDynamicTrustStore
	}{
		{
			name: "threshold reached",
			store: &fakeDynamicTrustStore{resizeDecision: dynamicTrustDecision{
				Trusted: false, UserThreshold: 8_000, TokenThreshold: 8_000,
			}},
		},
		{
			name:  "redis unavailable",
			store: &fakeDynamicTrustStore{resizeErr: errors.New("redis timeout")},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			_, session := setupDynamicTrustTest(t, testCase.store)
			session.trusted = true
			session.dynamicTrust = &dynamicTrustReservation{
				store: testCase.store, requestID: "request-dynamic-trust", userID: session.relayInfo.UserId,
				tokenID: session.relayInfo.TokenId, amount: 1_000,
			}

			require.NoError(t, session.Reserve(2_000))
			assert.False(t, session.trusted)
			assert.Nil(t, session.dynamicTrust)
			assert.Equal(t, 2_000, session.preConsumedQuota)
			assert.Equal(t, 1, testCase.store.releaseCalls)
			assert.Equal(t, 2_000, session.funding.(*fakeWalletFunding).preConsumed)
		})
	}
}

func TestStaticTrustUsesCustomMinimum(t *testing.T) {
	store := &fakeDynamicTrustStore{}
	c, session := setupDynamicTrustTest(t, store)
	common.TrustQuotaDynamicEnabled = false
	common.TrustQuotaMinUSD = 50
	session.relayInfo.UserQuota = common.QuotaFromFloat(40 * common.QuotaPerUnit)

	assert.False(t, session.shouldTrust(c, 1_000))
	session.relayInfo.UserQuota = common.QuotaFromFloat(60 * common.QuotaPerUnit)
	assert.True(t, session.shouldTrust(c, 1_000))
	assert.Zero(t, store.acquireCalls)
}

func TestRedisDynamicTrustConcurrentAcquireAndRelease(t *testing.T) {
	server := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: server.Addr()})
	t.Cleanup(func() { _ = client.Close() })
	store := &redisDynamicTrustStore{client: client}

	const requests = 100
	var trustedCount atomic.Int64
	trusted := make(chan *dynamicTrustReservation, requests)
	errors := make(chan error, requests)
	var wg sync.WaitGroup
	for i := 0; i < requests; i++ {
		wg.Add(1)
		go func(index int) {
			defer wg.Done()
			params := dynamicTrustAcquireParams{
				RequestID: fmt.Sprintf("concurrent-%d", index), UserID: 500, TokenID: 700,
				Amount: 100, UserQuota: 10_000, TokenQuota: 10_000, MinQuota: 1_000, FactorMillis: 1_500,
			}
			decision, err := store.Acquire(context.Background(), params)
			if err != nil {
				errors <- err
				return
			}
			if decision.Trusted {
				trustedCount.Add(1)
				trusted <- &dynamicTrustReservation{
					store: store, requestID: params.RequestID, userID: params.UserID, tokenID: params.TokenID,
				}
			}
		}(i)
	}
	wg.Wait()
	close(trusted)
	close(errors)
	for err := range errors {
		require.NoError(t, err)
	}

	assert.Equal(t, int64(66), trustedCount.Load())
	keys := dynamicTrustKeys(500)
	assert.Equal(t, "6600", server.HGet(keys[2], "user"))
	assert.Equal(t, "6600", server.HGet(keys[2], "token:700"))

	for reservation := range trusted {
		require.NoError(t, store.Release(context.Background(), reservation))
	}
	assert.Equal(t, "0", server.HGet(keys[2], "user"))
	assert.Equal(t, "0", server.HGet(keys[2], "token:700"))
}

func TestRedisDynamicTrustIdempotentResizeSettleAndRelease(t *testing.T) {
	server := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: server.Addr()})
	t.Cleanup(func() { _ = client.Close() })
	store := &redisDynamicTrustStore{client: client}
	params := dynamicTrustAcquireParams{
		RequestID: "idempotent-request", UserID: 501, TokenID: 701,
		Amount: 1_000, UserQuota: 100_000, TokenQuota: 100_000, MinQuota: 5_000, FactorMillis: 1_500,
	}

	decision, err := store.Acquire(context.Background(), params)
	require.NoError(t, err)
	require.True(t, decision.Trusted)
	decision, err = store.Acquire(context.Background(), params)
	require.NoError(t, err)
	require.True(t, decision.Trusted)
	keys := dynamicTrustKeys(params.UserID)
	assert.Equal(t, "1000", server.HGet(keys[2], "user"))

	reservation := &dynamicTrustReservation{
		store: store, requestID: params.RequestID, userID: params.UserID, tokenID: params.TokenID,
		amount: params.Amount, userQuota: params.UserQuota, tokenQuota: params.TokenQuota,
		minQuota: params.MinQuota, factorMillis: params.FactorMillis,
	}
	decision, err = store.Resize(context.Background(), reservation, 2_000)
	require.NoError(t, err)
	require.True(t, decision.Trusted)
	assert.Equal(t, "2000", server.HGet(keys[2], "user"))

	require.NoError(t, store.Settle(context.Background(), reservation, 1_500, 7*time.Second))
	assert.Equal(t, "1500", server.HGet(keys[2], "user"))
	require.NoError(t, store.Release(context.Background(), reservation))
	require.NoError(t, store.Release(context.Background(), reservation))
	assert.Equal(t, "0", server.HGet(keys[2], "user"))
}

func TestRedisDynamicTrustAcquireCleansExpiredReservation(t *testing.T) {
	server := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: server.Addr()})
	t.Cleanup(func() { _ = client.Close() })
	store := &redisDynamicTrustStore{client: client}
	first := dynamicTrustAcquireParams{
		RequestID: "expired-request", UserID: 502, TokenID: 702,
		Amount: 2_000, UserQuota: 100_000, TokenQuota: 100_000, MinQuota: 5_000, FactorMillis: 1_500,
	}
	decision, err := store.Acquire(context.Background(), first)
	require.NoError(t, err)
	require.True(t, decision.Trusted)
	keys := dynamicTrustKeys(first.UserID)
	require.NoError(t, client.ZAdd(context.Background(), keys[0], &redis.Z{
		Score: float64(time.Now().Add(-time.Second).UnixMilli()), Member: first.RequestID,
	}).Err())

	second := first
	second.RequestID = "replacement-request"
	second.Amount = 1_000
	decision, err = store.Acquire(context.Background(), second)
	require.NoError(t, err)
	require.True(t, decision.Trusted)
	assert.Equal(t, 1_000, decision.UserPending)
	assert.Equal(t, "1000", server.HGet(keys[2], "user"))
	assert.Equal(t, "1000", server.HGet(keys[2], "token:702"))
}

func TestRedisDynamicTrustAggregatesWalletAndSeparatesTokens(t *testing.T) {
	server := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: server.Addr()})
	t.Cleanup(func() { _ = client.Close() })
	store := &redisDynamicTrustStore{client: client}

	first := dynamicTrustAcquireParams{
		RequestID: "first-token", UserID: 503, TokenID: 703,
		Amount: 2_000, UserQuota: 100_000, TokenQuota: 100_000, MinQuota: 500, FactorMillis: 1_500,
	}
	decision, err := store.Acquire(context.Background(), first)
	require.NoError(t, err)
	require.True(t, decision.Trusted)

	second := first
	second.RequestID = "second-token"
	second.TokenID = 704
	second.Amount = 1_000
	decision, err = store.Acquire(context.Background(), second)
	require.NoError(t, err)
	require.True(t, decision.Trusted)
	assert.Equal(t, 3_000, decision.UserPending)
	assert.Equal(t, 1_000, decision.TokenPending)

	denied := second
	denied.RequestID = "second-token-denied"
	denied.TokenQuota = 2_500
	decision, err = store.Acquire(context.Background(), denied)
	require.NoError(t, err)
	assert.False(t, decision.Trusted)
	assert.Equal(t, 3_000, decision.TokenThreshold)

	unlimited := second
	unlimited.RequestID = "unlimited-token"
	unlimited.TokenID = 705
	unlimited.TokenUnlimited = true
	decision, err = store.Acquire(context.Background(), unlimited)
	require.NoError(t, err)
	require.True(t, decision.Trusted)
	assert.Equal(t, 4_000, decision.UserPending)
	assert.Zero(t, decision.TokenPending)
	assert.Zero(t, decision.TokenThreshold)

	keys := dynamicTrustKeys(first.UserID)
	assert.Equal(t, "4000", server.HGet(keys[2], "user"))
	assert.Equal(t, "2000", server.HGet(keys[2], "token:703"))
	assert.Equal(t, "1000", server.HGet(keys[2], "token:704"))
	assert.Equal(t, "", server.HGet(keys[2], "token:705"))
}
