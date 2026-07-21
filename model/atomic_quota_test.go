package model

import (
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/QuantumNous/new-api/common"

	"github.com/alicebob/miniredis/v2"
	"github.com/go-redis/redis/v8"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func setupAtomicQuotaTest(t *testing.T, userQuota, tokenQuota int) *AtomicQuotaReservation {
	t.Helper()
	server := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: server.Addr()})
	oldRDB := common.RDB
	oldRedisEnabled := common.RedisEnabled
	oldBatchEnabled := common.BatchUpdateEnabled
	common.RDB = client
	common.RedisEnabled = true
	common.BatchUpdateEnabled = true
	resetBatchUpdateStores()
	t.Cleanup(func() {
		_ = client.Close()
		common.RDB = oldRDB
		common.RedisEnabled = oldRedisEnabled
		common.BatchUpdateEnabled = oldBatchEnabled
		resetBatchUpdateStores()
	})

	userID := 901
	token := &Token{Id: 902, UserId: userID, Key: "atomic-quota-token", RemainQuota: tokenQuota}
	require.NoError(t, common.RedisHSetObj(getUserCacheKey(userID), &UserBase{
		Id: userID, Quota: userQuota, AuthVersion: 1, CacheSchema: userCacheSchemaVersion,
	}, 0))
	require.NoError(t, cacheSetToken(*token))
	return &AtomicQuotaReservation{
		RequestID: "atomic-request",
		UserID:    userID,
		TokenID:   token.Id,
		TokenKey:  token.Key,
		Amount:    100,
	}
}

func TestAtomicQuotaLifecycleIsIdempotent(t *testing.T) {
	reservation := setupAtomicQuotaTest(t, 1000, 1000)

	result, err := AcquireAtomicQuota(reservation)
	require.NoError(t, err)
	assert.Equal(t, "reserved", result.Status)
	assert.Equal(t, 900, result.UserQuota)

	result, err = AcquireAtomicQuota(reservation)
	require.NoError(t, err)
	assert.True(t, result.AlreadyApplied)

	result, err = SettleAtomicQuota(reservation, 80)
	require.NoError(t, err)
	assert.Equal(t, -20, result.Delta)
	assert.Equal(t, 920, result.UserQuota)

	result, err = SettleAtomicQuota(reservation, 80)
	require.NoError(t, err)
	assert.True(t, result.AlreadyApplied)
	batchUpdateLocks[BatchUpdateTypeUserQuota].Lock()
	userDelta := batchUpdateStores[BatchUpdateTypeUserQuota][reservation.UserID]
	batchUpdateLocks[BatchUpdateTypeUserQuota].Unlock()
	batchUpdateLocks[BatchUpdateTypeTokenQuota].Lock()
	tokenDelta := batchUpdateStores[BatchUpdateTypeTokenQuota][reservation.TokenID]
	batchUpdateLocks[BatchUpdateTypeTokenQuota].Unlock()
	assert.Equal(t, -80, userDelta)
	assert.Equal(t, -80, tokenDelta)
}

func TestAtomicQuotaConcurrentAcquireDoesNotOversubscribe(t *testing.T) {
	base := setupAtomicQuotaTest(t, 500, 500)
	const requests = 100
	var successes atomic.Int64
	var insufficient atomic.Int64
	var wg sync.WaitGroup

	for i := 0; i < requests; i++ {
		wg.Add(1)
		go func(index int) {
			defer wg.Done()
			reservation := *base
			reservation.RequestID = fmt.Sprintf("atomic-concurrent-%d", index)
			reservation.Amount = 10
			_, err := AcquireAtomicQuota(&reservation)
			switch {
			case err == nil:
				successes.Add(1)
			case errors.Is(err, ErrAtomicUserQuotaInsufficient), errors.Is(err, ErrAtomicTokenQuotaInsufficient):
				insufficient.Add(1)
			default:
				t.Errorf("unexpected atomic quota error: %v", err)
			}
		}(i)
	}
	wg.Wait()

	assert.EqualValues(t, 50, successes.Load())
	assert.EqualValues(t, 50, insufficient.Load())
	quota, err := getUserQuotaCache(base.UserID)
	require.NoError(t, err)
	assert.Zero(t, quota)
}

func TestAtomicQuotaWarmsMissingCachesFromDatabase(t *testing.T) {
	truncateTables(t)
	server := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: server.Addr()})
	oldRDB := common.RDB
	oldRedisEnabled := common.RedisEnabled
	oldBatchEnabled := common.BatchUpdateEnabled
	common.RDB = client
	common.RedisEnabled = true
	common.BatchUpdateEnabled = true
	resetBatchUpdateStores()
	t.Cleanup(func() {
		_ = client.Close()
		common.RDB = oldRDB
		common.RedisEnabled = oldRedisEnabled
		common.BatchUpdateEnabled = oldBatchEnabled
		resetBatchUpdateStores()
	})

	user := &User{Id: 903, Username: "atomic-warm-user", Password: "password", Status: common.UserStatusEnabled, Quota: 1000}
	require.NoError(t, DB.Create(user).Error)
	token := &Token{
		UserId: user.Id, Name: "atomic-warm-token", Key: "atomic-warm-key", Status: common.TokenStatusEnabled,
		CreatedTime: 1, AccessedTime: 1, ExpiredTime: -1, RemainQuota: 1000,
	}
	require.NoError(t, DB.Create(token).Error)
	reservation := &AtomicQuotaReservation{
		RequestID: "atomic-warm-request", UserID: user.Id, TokenID: token.Id, TokenKey: token.Key, Amount: 100,
	}

	result, err := AcquireAtomicQuota(reservation)

	require.NoError(t, err)
	assert.Equal(t, 900, result.UserQuota)
	assert.Equal(t, 900, result.TokenQuota)
}
