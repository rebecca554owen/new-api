package model

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/QuantumNous/new-api/common"

	"github.com/go-redis/redis/v8"
)

const (
	atomicQuotaTimeout   = 50 * time.Millisecond
	atomicQuotaRecordTTL = 7 * 24 * time.Hour
	atomicQuotaInitTTL   = 2 * time.Second
)

var (
	ErrAtomicQuotaUnavailable       = errors.New("atomic quota service unavailable")
	ErrAtomicUserQuotaInsufficient  = errors.New("user quota is insufficient")
	ErrAtomicTokenQuotaInsufficient = errors.New("token quota is insufficient")
	ErrAtomicQuotaConflict          = errors.New("atomic quota reservation state conflict")
)

type AtomicQuotaReservation struct {
	RequestID      string
	UserID         int
	TokenID        int
	TokenKey       string
	TokenUnlimited bool
	Amount         int
}

type AtomicQuotaResult struct {
	Status         string
	UserQuota      int
	TokenQuota     int
	Delta          int
	Duration       time.Duration
	AlreadyApplied bool
}

func atomicQuotaKeys(reservation *AtomicQuotaReservation) []string {
	tokenKey := "billing:atomic:unlimited"
	if !reservation.TokenUnlimited {
		tokenKey = fmt.Sprintf("token:%s", common.GenerateHMAC(reservation.TokenKey))
	}
	recordKey := fmt.Sprintf("billing:atomic:reservation:%d:%s", reservation.UserID, common.GenerateHMAC(reservation.RequestID))
	return []string{getUserCacheKey(reservation.UserID), tokenKey, recordKey}
}

var atomicQuotaAcquireScript = redis.NewScript(`
local amount = tonumber(ARGV[1])
local tokenLimited = ARGV[2] == '1'
local ttl = tonumber(ARGV[3])
local state = redis.call('HGET', KEYS[3], 'state')
if state then
  local old = tonumber(redis.call('HGET', KEYS[3], 'amount')) or 0
  if state == 'active' and old == amount then
    return {2, tonumber(redis.call('HGET', KEYS[1], 'Quota')) or 0,
      tokenLimited and (tonumber(redis.call('HGET', KEYS[2], 'RemainQuota')) or 0) or 0}
  end
  return {-4, 0, 0}
end
local userQuota = tonumber(redis.call('HGET', KEYS[1], 'Quota'))
if not userQuota then return {-2, 0, 0} end
local tokenQuota = 0
if tokenLimited then
  tokenQuota = tonumber(redis.call('HGET', KEYS[2], 'RemainQuota'))
  if not tokenQuota then return {-3, userQuota, 0} end
end
if userQuota < amount then return {0, userQuota, tokenQuota} end
if tokenLimited and tokenQuota < amount then return {-1, userQuota, tokenQuota} end
userQuota = redis.call('HINCRBY', KEYS[1], 'Quota', -amount)
if tokenLimited then tokenQuota = redis.call('HINCRBY', KEYS[2], 'RemainQuota', -amount) end
redis.call('HSET', KEYS[3], 'state', 'active', 'amount', amount)
redis.call('PEXPIRE', KEYS[3], ttl)
return {1, userQuota, tokenQuota}
`)

var atomicQuotaResizeScript = redis.NewScript(`
local target = tonumber(ARGV[1])
local tokenLimited = ARGV[2] == '1'
local ttl = tonumber(ARGV[3])
local state = redis.call('HGET', KEYS[3], 'state')
if state ~= 'active' then return {-4, 0, 0, 0} end
local old = tonumber(redis.call('HGET', KEYS[3], 'amount')) or 0
if target <= old then
  return {2, tonumber(redis.call('HGET', KEYS[1], 'Quota')) or 0,
    tokenLimited and (tonumber(redis.call('HGET', KEYS[2], 'RemainQuota')) or 0) or 0, 0}
end
local delta = target - old
local userQuota = tonumber(redis.call('HGET', KEYS[1], 'Quota'))
if not userQuota then return {-2, 0, 0, delta} end
local tokenQuota = 0
if tokenLimited then
  tokenQuota = tonumber(redis.call('HGET', KEYS[2], 'RemainQuota'))
  if not tokenQuota then return {-3, userQuota, 0, delta} end
end
if userQuota < delta then return {0, userQuota, tokenQuota, delta} end
if tokenLimited and tokenQuota < delta then return {-1, userQuota, tokenQuota, delta} end
userQuota = redis.call('HINCRBY', KEYS[1], 'Quota', -delta)
if tokenLimited then tokenQuota = redis.call('HINCRBY', KEYS[2], 'RemainQuota', -delta) end
redis.call('HSET', KEYS[3], 'amount', target)
redis.call('PEXPIRE', KEYS[3], ttl)
return {1, userQuota, tokenQuota, delta}
`)

var atomicQuotaSettleScript = redis.NewScript(`
local actual = tonumber(ARGV[1])
local tokenLimited = ARGV[2] == '1'
local ttl = tonumber(ARGV[3])
local state = redis.call('HGET', KEYS[3], 'state')
if state == 'settled' then
  return {2, tonumber(redis.call('HGET', KEYS[1], 'Quota')) or 0,
    tokenLimited and (tonumber(redis.call('HGET', KEYS[2], 'RemainQuota')) or 0) or 0, 0, 0}
end
if state ~= 'active' then return {-4, 0, 0, 0, 0} end
local old = tonumber(redis.call('HGET', KEYS[3], 'amount')) or 0
local delta = actual - old
local userQuota = tonumber(redis.call('HGET', KEYS[1], 'Quota'))
if not userQuota then return {-2, 0, 0, delta, 0} end
local tokenQuota = 0
if tokenLimited then
  tokenQuota = tonumber(redis.call('HGET', KEYS[2], 'RemainQuota'))
  if not tokenQuota then return {-3, userQuota, 0, delta, 0} end
end
if delta ~= 0 then
  userQuota = redis.call('HINCRBY', KEYS[1], 'Quota', -delta)
  if tokenLimited then tokenQuota = redis.call('HINCRBY', KEYS[2], 'RemainQuota', -delta) end
end
local debt = 0
if userQuota < 0 or (tokenLimited and tokenQuota < 0) then debt = 1 end
local result = debt == 1 and 'settled_debt' or 'settled'
redis.call('HSET', KEYS[3], 'state', 'settled', 'actual', actual, 'delta', delta, 'result', result)
redis.call('PEXPIRE', KEYS[3], ttl)
return {1, userQuota, tokenQuota, delta, debt}
`)

var atomicQuotaRefundScript = redis.NewScript(`
local tokenLimited = ARGV[1] == '1'
local ttl = tonumber(ARGV[2])
local state = redis.call('HGET', KEYS[3], 'state')
if state == 'refunded' then
  return {2, tonumber(redis.call('HGET', KEYS[1], 'Quota')) or 0,
    tokenLimited and (tonumber(redis.call('HGET', KEYS[2], 'RemainQuota')) or 0) or 0, 0}
end
if state ~= 'active' then return {-4, 0, 0, 0} end
local amount = tonumber(redis.call('HGET', KEYS[3], 'amount')) or 0
local userQuota = tonumber(redis.call('HGET', KEYS[1], 'Quota'))
if not userQuota then return {-2, 0, 0, amount} end
local tokenQuota = 0
if tokenLimited then
  tokenQuota = tonumber(redis.call('HGET', KEYS[2], 'RemainQuota'))
  if not tokenQuota then return {-3, userQuota, 0, amount} end
end
userQuota = redis.call('HINCRBY', KEYS[1], 'Quota', amount)
if tokenLimited then tokenQuota = redis.call('HINCRBY', KEYS[2], 'RemainQuota', amount) end
redis.call('HSET', KEYS[3], 'state', 'refunded', 'result', 'refunded')
redis.call('PEXPIRE', KEYS[3], ttl)
return {1, userQuota, tokenQuota, amount}
`)

func AcquireAtomicQuota(reservation *AtomicQuotaReservation) (AtomicQuotaResult, error) {
	if reservation == nil || reservation.RequestID == "" || reservation.Amount < 0 {
		return AtomicQuotaResult{}, ErrAtomicQuotaConflict
	}
	return runAtomicQuotaOperation(reservation, atomicQuotaAcquireScript, reservation.Amount)
}

func ResizeAtomicQuota(reservation *AtomicQuotaReservation, target int) (AtomicQuotaResult, error) {
	if reservation == nil || target < reservation.Amount {
		return AtomicQuotaResult{}, ErrAtomicQuotaConflict
	}
	result, err := runAtomicQuotaOperation(reservation, atomicQuotaResizeScript, target)
	if err == nil && !result.AlreadyApplied {
		reservation.Amount = target
	}
	return result, err
}

func SettleAtomicQuota(reservation *AtomicQuotaReservation, actual int) (AtomicQuotaResult, error) {
	if reservation == nil || actual < 0 {
		return AtomicQuotaResult{}, ErrAtomicQuotaConflict
	}
	return runAtomicQuotaOperation(reservation, atomicQuotaSettleScript, actual)
}

func RefundAtomicQuota(reservation *AtomicQuotaReservation) (AtomicQuotaResult, error) {
	if reservation == nil {
		return AtomicQuotaResult{}, ErrAtomicQuotaConflict
	}
	return runAtomicQuotaOperation(reservation, atomicQuotaRefundScript)
}

func runAtomicQuotaOperation(reservation *AtomicQuotaReservation, script *redis.Script, values ...interface{}) (AtomicQuotaResult, error) {
	started := time.Now()
	if !common.RedisEnabled || common.RDB == nil || !common.BatchUpdateEnabled {
		return AtomicQuotaResult{Duration: time.Since(started)}, ErrAtomicQuotaUnavailable
	}
	args := append(values, boolArg(!reservation.TokenUnlimited), atomicQuotaRecordTTL.Milliseconds())
	var result AtomicQuotaResult
	var err error
	for attempt := 0; attempt < 3; attempt++ {
		result, err = runAtomicQuotaScript(reservation, script, args...)
		if !errors.Is(err, errAtomicUserCacheMissing) && !errors.Is(err, errAtomicTokenCacheMissing) {
			break
		}
		if warmErr := warmAtomicQuotaCaches(reservation, errors.Is(err, errAtomicUserCacheMissing), errors.Is(err, errAtomicTokenCacheMissing)); warmErr != nil {
			return AtomicQuotaResult{Duration: time.Since(started)}, fmt.Errorf("%w: %v", ErrAtomicQuotaUnavailable, warmErr)
		}
	}
	result.Duration = time.Since(started)
	if err != nil {
		return result, err
	}
	if result.AlreadyApplied {
		return result, nil
	}
	switch script {
	case atomicQuotaAcquireScript:
		result.Status = "reserved"
	case atomicQuotaResizeScript:
		result.Status = "resized"
	case atomicQuotaSettleScript:
		if result.Status != "settled_debt" {
			result.Status = "settled"
		}
	case atomicQuotaRefundScript:
		result.Status = "refunded"
	}

	balanceDelta := -result.Delta
	if script == atomicQuotaAcquireScript {
		balanceDelta = -reservation.Amount
	}
	if script == atomicQuotaRefundScript {
		balanceDelta = result.Delta
	}
	addNewRecord(BatchUpdateTypeUserQuota, reservation.UserID, balanceDelta)
	if !reservation.TokenUnlimited {
		addNewRecord(BatchUpdateTypeTokenQuota, reservation.TokenID, balanceDelta)
	}
	return result, nil
}

var (
	errAtomicUserCacheMissing  = errors.New("atomic user quota cache is missing")
	errAtomicTokenCacheMissing = errors.New("atomic token quota cache is missing")
)

func runAtomicQuotaScript(reservation *AtomicQuotaReservation, script *redis.Script, args ...interface{}) (AtomicQuotaResult, error) {
	ctx, cancel := context.WithTimeout(context.Background(), atomicQuotaTimeout)
	defer cancel()
	values, err := script.Run(ctx, common.RDB, atomicQuotaKeys(reservation), args...).Slice()
	if err != nil {
		return AtomicQuotaResult{}, fmt.Errorf("%w: %v", ErrAtomicQuotaUnavailable, err)
	}
	parsed := make([]int64, len(values))
	for i, value := range values {
		switch v := value.(type) {
		case int64:
			parsed[i] = v
		case string:
			parsed[i], err = strconv.ParseInt(v, 10, 64)
		default:
			err = fmt.Errorf("unexpected result type %T", value)
		}
		if err != nil {
			return AtomicQuotaResult{}, fmt.Errorf("%w: %v", ErrAtomicQuotaUnavailable, err)
		}
	}
	if len(parsed) < 3 {
		return AtomicQuotaResult{}, ErrAtomicQuotaUnavailable
	}
	result := AtomicQuotaResult{UserQuota: int(parsed[1]), TokenQuota: int(parsed[2])}
	if len(parsed) > 3 {
		result.Delta = int(parsed[3])
	}
	switch parsed[0] {
	case 2:
		result.Status = "duplicate"
		result.AlreadyApplied = true
		return result, nil
	case 1:
		result.Status = "applied"
		if len(parsed) > 4 && parsed[4] == 1 {
			result.Status = "settled_debt"
		}
		return result, nil
	case 0:
		return result, ErrAtomicUserQuotaInsufficient
	case -1:
		return result, ErrAtomicTokenQuotaInsufficient
	case -2:
		return result, errAtomicUserCacheMissing
	case -3:
		return result, errAtomicTokenCacheMissing
	default:
		return result, ErrAtomicQuotaConflict
	}
}

func warmAtomicQuotaCaches(reservation *AtomicQuotaReservation, warmUser, warmToken bool) error {
	ctx, cancel := context.WithTimeout(context.Background(), atomicQuotaInitTTL)
	defer cancel()
	lockKey := fmt.Sprintf("billing:atomic:init:%d", reservation.UserID)
	locked, err := common.RDB.SetNX(ctx, lockKey, "1", atomicQuotaInitTTL).Result()
	if err != nil {
		return err
	}
	if !locked {
		ticker := time.NewTicker(5 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-ticker.C:
				userReady := !warmUser || common.RDB.HExists(ctx, getUserCacheKey(reservation.UserID), "Quota").Val()
				tokenReady := !warmToken || reservation.TokenUnlimited || common.RDB.HExists(ctx, atomicQuotaKeys(reservation)[1], "RemainQuota").Val()
				if userReady && tokenReady {
					return nil
				}
			}
		}
	}
	defer common.RDB.Del(context.Background(), lockKey)

	if warmUser {
		user, err := GetUserById(reservation.UserID, true)
		if err != nil {
			return err
		}
		if err := populateUserCache(*user); err != nil {
			return err
		}
	}
	if !warmToken || reservation.TokenUnlimited {
		return nil
	}
	token, err := GetTokenByKey(reservation.TokenKey, true)
	if err != nil {
		return err
	}
	if token.Id != reservation.TokenID {
		return ErrAtomicQuotaConflict
	}
	return cacheSetToken(*token)
}

func boolArg(value bool) string {
	if value {
		return "1"
	}
	return "0"
}
