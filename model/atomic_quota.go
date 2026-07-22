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
	RequestID             string
	UserID                int
	TokenID               int
	TokenKey              string
	TokenUnlimited        bool
	Amount                int
	DynamicTrustRequestID string
}

type AtomicQuotaResult struct {
	Status         string
	UserQuota      int
	TokenQuota     int
	Delta          int
	Duration       time.Duration
	AlreadyApplied bool
	TrustConverted bool
}

func atomicQuotaKeys(reservation *AtomicQuotaReservation) []string {
	tokenKey := "billing:atomic:unlimited"
	if !reservation.TokenUnlimited {
		tokenKey = fmt.Sprintf("token:%s", common.GenerateHMAC(reservation.TokenKey))
	}
	recordKey := fmt.Sprintf("billing:atomic:reservation:%d:%s", reservation.UserID, common.GenerateHMAC(reservation.RequestID))
	keys := []string{getUserCacheKey(reservation.UserID), tokenKey, recordKey}
	return append(keys, common.DynamicTrustRedisKeys(reservation.UserID)...)
}

var atomicQuotaAcquireScript = redis.NewScript(`
local function cleanupTrust(now)
  local expired = redis.call('ZRANGEBYSCORE', KEYS[4], '-inf', now)
  for _, id in ipairs(expired) do
    local amount = tonumber(redis.call('HGET', KEYS[5], id .. ':amount')) or 0
    local token = redis.call('HGET', KEYS[5], id .. ':token') or ''
    if amount ~= 0 then
      redis.call('HINCRBY', KEYS[6], 'user', -amount)
      if token ~= '' and token ~= '0' then
        redis.call('HINCRBY', KEYS[6], 'token:' .. token, -amount)
      end
    end
    redis.call('HDEL', KEYS[5], id .. ':amount', id .. ':token')
    redis.call('ZREM', KEYS[4], id)
  end
end

local amount = tonumber(ARGV[1])
local tokenLimited = ARGV[2] == '1'
local ttl = tonumber(ARGV[3])
local now = tonumber(ARGV[4])
local trustID = ARGV[5]
local tokenID = ARGV[6]
cleanupTrust(now)
local state = redis.call('HGET', KEYS[3], 'state')
if state then
  local old = tonumber(redis.call('HGET', KEYS[3], 'amount')) or 0
  if state == 'active' and old == amount then
    local converted = 0
    if trustID ~= '' then
      local trustAmount = tonumber(redis.call('HGET', KEYS[5], trustID .. ':amount')) or 0
      local trustToken = redis.call('HGET', KEYS[5], trustID .. ':token') or ''
      if trustAmount > 0 then
        if trustToken ~= tokenID then return {-4, 0, 0} end
        redis.call('HINCRBY', KEYS[6], 'user', -trustAmount)
        if trustToken ~= '0' then redis.call('HINCRBY', KEYS[6], 'token:' .. trustToken, -trustAmount) end
        redis.call('HDEL', KEYS[5], trustID .. ':amount', trustID .. ':token')
        redis.call('ZREM', KEYS[4], trustID)
        converted = 1
      end
    end
    return {2, tonumber(redis.call('HGET', KEYS[1], 'Quota')) or 0,
      tokenLimited and (tonumber(redis.call('HGET', KEYS[2], 'RemainQuota')) or 0) or 0, 0, 0, converted}
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
local ownTrustAmount = 0
local ownTrustToken = ''
if trustID ~= '' then
  ownTrustAmount = tonumber(redis.call('HGET', KEYS[5], trustID .. ':amount')) or 0
  ownTrustToken = redis.call('HGET', KEYS[5], trustID .. ':token') or ''
  if ownTrustAmount > 0 and ownTrustToken ~= tokenID then return {-4, 0, 0} end
end
local userPending = tonumber(redis.call('HGET', KEYS[6], 'user')) or 0
if userPending < 0 or userPending < ownTrustAmount then return {-4, 0, 0} end
local otherUserPending = userPending - ownTrustAmount
local tokenPending = 0
local otherTokenPending = 0
if tokenLimited then
  tokenPending = tonumber(redis.call('HGET', KEYS[6], 'token:' .. tokenID)) or 0
  if tokenPending < 0 or tokenPending < ownTrustAmount then return {-4, 0, 0} end
  otherTokenPending = tokenPending - ownTrustAmount
end
if userQuota - otherUserPending < amount then return {0, userQuota, tokenQuota} end
if tokenLimited and tokenQuota - otherTokenPending < amount then return {-1, userQuota, tokenQuota} end
userQuota = redis.call('HINCRBY', KEYS[1], 'Quota', -amount)
if tokenLimited then tokenQuota = redis.call('HINCRBY', KEYS[2], 'RemainQuota', -amount) end
local converted = 0
if ownTrustAmount > 0 then
  redis.call('HINCRBY', KEYS[6], 'user', -ownTrustAmount)
  if ownTrustToken ~= '0' then redis.call('HINCRBY', KEYS[6], 'token:' .. ownTrustToken, -ownTrustAmount) end
  redis.call('HDEL', KEYS[5], trustID .. ':amount', trustID .. ':token')
  redis.call('ZREM', KEYS[4], trustID)
  converted = 1
end
redis.call('HSET', KEYS[3], 'state', 'active', 'amount', amount)
redis.call('PEXPIRE', KEYS[3], ttl)
return {1, userQuota, tokenQuota, amount, 0, converted}
`)

var atomicQuotaResizeScript = redis.NewScript(`
local function cleanupTrust(now)
  local expired = redis.call('ZRANGEBYSCORE', KEYS[4], '-inf', now)
  for _, id in ipairs(expired) do
    local amount = tonumber(redis.call('HGET', KEYS[5], id .. ':amount')) or 0
    local token = redis.call('HGET', KEYS[5], id .. ':token') or ''
    if amount ~= 0 then
      redis.call('HINCRBY', KEYS[6], 'user', -amount)
      if token ~= '' and token ~= '0' then
        redis.call('HINCRBY', KEYS[6], 'token:' .. token, -amount)
      end
    end
    redis.call('HDEL', KEYS[5], id .. ':amount', id .. ':token')
    redis.call('ZREM', KEYS[4], id)
  end
end

local target = tonumber(ARGV[1])
local tokenLimited = ARGV[2] == '1'
local ttl = tonumber(ARGV[3])
local now = tonumber(ARGV[4])
local tokenID = ARGV[6]
cleanupTrust(now)
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
local userPending = tonumber(redis.call('HGET', KEYS[6], 'user')) or 0
if userPending < 0 then return {-4, 0, 0, delta} end
local tokenPending = 0
if tokenLimited then
  tokenPending = tonumber(redis.call('HGET', KEYS[6], 'token:' .. tokenID)) or 0
  if tokenPending < 0 then return {-4, 0, 0, delta} end
end
if userQuota - userPending < delta then return {0, userQuota, tokenQuota, delta} end
if tokenLimited and tokenQuota - tokenPending < delta then return {-1, userQuota, tokenQuota, delta} end
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

// CompensateAtomicQuotaReservation offsets the batch records created when an
// atomic reservation was acquired but Redis could not process its refund.
// It deliberately uses the normal batch-update path: the original reservation
// has already queued a negative delta, so a direct database increment would
// over-credit the account once that queued debit is flushed.
func CompensateAtomicQuotaReservation(reservation *AtomicQuotaReservation) error {
	if err := RecordAtomicQuotaRefund(reservation); err != nil {
		return err
	}
	if common.RedisEnabled && common.RDB != nil {
		if err := invalidateUserCache(reservation.UserID); err != nil {
			common.SysLog("failed to invalidate user quota cache after atomic compensation: " + err.Error())
		}
		if !reservation.TokenUnlimited {
			if err := cacheDeleteToken(reservation.TokenKey); err != nil {
				common.SysLog("failed to invalidate token quota cache after atomic compensation: " + err.Error())
			}
		}
	}
	return nil
}

// RecordAtomicQuotaRefund records the database batch compensation without
// touching Redis. It is used when a retry confirms that Redis already applied
// the refund but the original response was lost before accounting was queued.
func RecordAtomicQuotaRefund(reservation *AtomicQuotaReservation) error {
	if reservation == nil || reservation.Amount < 0 {
		return ErrAtomicQuotaConflict
	}
	if !common.BatchUpdateEnabled {
		return ErrAtomicQuotaUnavailable
	}
	addNewRecord(BatchUpdateTypeUserQuota, reservation.UserID, reservation.Amount)
	if !reservation.TokenUnlimited {
		addNewRecord(BatchUpdateTypeTokenQuota, reservation.TokenID, reservation.Amount)
	}
	return nil
}

func runAtomicQuotaOperation(reservation *AtomicQuotaReservation, script *redis.Script, values ...interface{}) (AtomicQuotaResult, error) {
	started := time.Now()
	if !common.RedisEnabled || common.RDB == nil || !common.BatchUpdateEnabled {
		return AtomicQuotaResult{Duration: time.Since(started)}, ErrAtomicQuotaUnavailable
	}
	tokenID := reservation.TokenID
	if reservation.TokenUnlimited {
		tokenID = 0
	}
	args := append(values, boolArg(!reservation.TokenUnlimited), atomicQuotaRecordTTL.Milliseconds(),
		time.Now().UnixMilli(), reservation.DynamicTrustRequestID, tokenID)
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
	if len(parsed) > 5 {
		result.TrustConverted = parsed[5] == 1
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
