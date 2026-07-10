package model

import (
	"errors"
	"sync"
	"testing"

	"github.com/QuantumNous/new-api/common"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func setupUserQuotaReservationTest(t *testing.T, id int, quota int, batchEnabled bool) {
	t.Helper()
	require.NoError(t, DB.Exec("DELETE FROM users").Error)
	resetBatchUpdateStores()

	oldRedisEnabled := common.RedisEnabled
	oldBatchUpdateEnabled := common.BatchUpdateEnabled
	common.RedisEnabled = false
	common.BatchUpdateEnabled = batchEnabled
	t.Cleanup(func() {
		common.RedisEnabled = oldRedisEnabled
		common.BatchUpdateEnabled = oldBatchUpdateEnabled
		resetBatchUpdateStores()
		_ = DB.Exec("DELETE FROM users").Error
	})

	require.NoError(t, DB.Create(&User{
		Id:       id,
		Username: "wallet-reservation-user",
		Status:   common.UserStatusEnabled,
		Quota:    quota,
	}).Error)
}

func getPersistedUserQuota(t *testing.T, id int) int {
	t.Helper()
	var quota int
	require.NoError(t, DB.Model(&User{}).Where("id = ?", id).Select("quota").Scan(&quota).Error)
	return quota
}

func TestReserveUserQuotaDeductsAffordableAmount(t *testing.T) {
	const userID = 27001
	setupUserQuotaReservationTest(t, userID, 100, false)

	require.NoError(t, ReserveUserQuota(userID, 60))
	assert.Equal(t, 40, getPersistedUserQuota(t, userID))
}

func TestReserveUserQuotaRejectsInsufficientFundsWithoutDebit(t *testing.T) {
	const userID = 27002
	setupUserQuotaReservationTest(t, userID, 40, false)

	err := ReserveUserQuota(userID, 60)
	require.ErrorIs(t, err, ErrInsufficientUserQuota)
	assert.Equal(t, 40, getPersistedUserQuota(t, userID))

	err = ReserveUserQuota(userID+1, 1)
	require.ErrorIs(t, err, ErrInsufficientUserQuota)
}

func TestReserveUserQuotaConcurrentNeverNegative(t *testing.T) {
	const (
		userID       = 27003
		initialQuota = 100
		reservation  = 30
		workers      = 8
	)
	// Reservations must bypass the batch queue even when it is globally enabled.
	setupUserQuotaReservationTest(t, userID, initialQuota, true)

	start := make(chan struct{})
	results := make(chan error, workers)
	var wg sync.WaitGroup
	wg.Add(workers)
	for i := 0; i < workers; i++ {
		go func() {
			defer wg.Done()
			<-start
			results <- ReserveUserQuota(userID, reservation)
		}()
	}
	close(start)
	wg.Wait()
	close(results)

	succeeded := 0
	rejected := 0
	for err := range results {
		switch {
		case err == nil:
			succeeded++
		case errors.Is(err, ErrInsufficientUserQuota):
			rejected++
		default:
			require.NoError(t, err)
		}
	}

	expectedSucceeded := initialQuota / reservation
	assert.Equal(t, expectedSucceeded, succeeded)
	assert.Equal(t, workers-expectedSucceeded, rejected)
	assert.Equal(t, initialQuota-(succeeded*reservation), getPersistedUserQuota(t, userID))
	assert.GreaterOrEqual(t, getPersistedUserQuota(t, userID), 0)

	batchUpdateLocks[BatchUpdateTypeUserQuota].Lock()
	pendingDelta := batchUpdateStores[BatchUpdateTypeUserQuota][userID]
	batchUpdateLocks[BatchUpdateTypeUserQuota].Unlock()
	assert.Zero(t, pendingDelta, "wallet reservations must not enter the batch queue")
}
