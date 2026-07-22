package service

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/QuantumNous/new-api/common"

	"github.com/bytedance/gopkg/util/gopool"
	"github.com/go-redis/redis/v8"
)

const (
	dynamicTrustRedisTimeout = 50 * time.Millisecond
	dynamicTrustLease        = 120 * time.Second
	dynamicTrustHeartbeat    = 40 * time.Second
)

type dynamicTrustAcquireParams struct {
	RequestID      string
	UserID         int
	TokenID        int
	TokenKey       string
	Amount         int
	TokenUnlimited bool
	MinQuota       int
	FactorMillis   int64
}

type dynamicTrustDecision struct {
	Trusted        bool
	UserThreshold  int
	TokenThreshold int
	UserPending    int
	TokenPending   int
}

type dynamicTrustStore interface {
	Acquire(ctx context.Context, params dynamicTrustAcquireParams) (dynamicTrustDecision, error)
	Resize(ctx context.Context, reservation *dynamicTrustReservation, targetQuota int) (dynamicTrustDecision, error)
	Refresh(ctx context.Context, reservation *dynamicTrustReservation) error
	Settle(ctx context.Context, reservation *dynamicTrustReservation, actualQuota int, grace time.Duration) error
	Release(ctx context.Context, reservation *dynamicTrustReservation) error
}

type dynamicTrustReservation struct {
	store           dynamicTrustStore
	requestID       string
	userID          int
	tokenID         int
	tokenKey        string
	amount          int
	tokenUnlimited  bool
	minQuota        int
	factorMillis    int64
	cancelHeartbeat context.CancelFunc
}

func (r *dynamicTrustReservation) startHeartbeat() {
	ctx, cancel := context.WithCancel(context.Background())
	r.cancelHeartbeat = cancel
	gopool.Go(func() {
		ticker := time.NewTicker(dynamicTrustHeartbeat)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if err := r.store.Refresh(ctx, r); err != nil {
					common.SysLog(fmt.Sprintf("failed to refresh dynamic trust reservation (userId=%d, tokenId=%d, requestId=%s): %s", r.userID, r.tokenID, r.requestID, err.Error()))
				}
			}
		}
	})
}

func (r *dynamicTrustReservation) stopHeartbeat() {
	if r != nil && r.cancelHeartbeat != nil {
		r.cancelHeartbeat()
		r.cancelHeartbeat = nil
	}
}

type redisDynamicTrustStore struct {
	client *redis.Client
}

func newRedisDynamicTrustStore() dynamicTrustStore {
	return &redisDynamicTrustStore{client: common.RDB}
}

var dynamicTrustStoreFactory = newRedisDynamicTrustStore

func dynamicTrustKeys(userID int) []string {
	return common.DynamicTrustRedisKeys(userID)
}

func dynamicTrustDecisionKeys(userID int, tokenKey string, tokenUnlimited bool) []string {
	keys := dynamicTrustKeys(userID)
	keys = append(keys, fmt.Sprintf("user:%d", userID))
	if tokenUnlimited {
		return append(keys, "billing:dynamic:unlimited")
	}
	return append(keys, fmt.Sprintf("token:%s", common.GenerateHMAC(tokenKey)))
}

var dynamicTrustAcquireScript = redis.NewScript(`
local function cleanup(now)
  local expired = redis.call('ZRANGEBYSCORE', KEYS[1], '-inf', now)
  for _, id in ipairs(expired) do
    local amount = tonumber(redis.call('HGET', KEYS[2], id .. ':amount')) or 0
    local token = redis.call('HGET', KEYS[2], id .. ':token') or ''
    if amount ~= 0 then
      redis.call('HINCRBY', KEYS[3], 'user', -amount)
      if token ~= '' and token ~= '0' then
        redis.call('HINCRBY', KEYS[3], 'token:' .. token, -amount)
      end
    end
    redis.call('HDEL', KEYS[2], id .. ':amount', id .. ':token')
    redis.call('ZREM', KEYS[1], id)
  end
end

local now = tonumber(ARGV[1])
local lease = tonumber(ARGV[2])
local id = ARGV[3]
local amount = tonumber(ARGV[4])
local token = ARGV[5]
local minQuota = tonumber(ARGV[6])
local factor = tonumber(ARGV[7])
cleanup(now)

local existing = redis.call('HGET', KEYS[2], id .. ':amount')
if existing then
  redis.call('ZADD', KEYS[1], now + lease, id)
  redis.call('PEXPIRE', KEYS[1], lease * 2)
  redis.call('PEXPIRE', KEYS[2], lease * 2)
  redis.call('PEXPIRE', KEYS[3], lease * 2)
  return {2, 0, 0, tonumber(redis.call('HGET', KEYS[3], 'user')) or 0,
    tonumber(redis.call('HGET', KEYS[3], 'token:' .. token)) or 0}
end

local userQuota = tonumber(redis.call('HGET', KEYS[4], 'Quota'))
if not userQuota then return {-2, 0, 0, 0, 0} end
local tokenQuota = 0
if token ~= '0' then
  tokenQuota = tonumber(redis.call('HGET', KEYS[5], 'RemainQuota'))
  if not tokenQuota then return {-3, 0, 0, 0, 0} end
end

local userPending = tonumber(redis.call('HGET', KEYS[3], 'user')) or 0
local prospectiveUser = userPending + amount
local userThreshold = math.floor((prospectiveUser * factor + 999) / 1000)
if userThreshold < minQuota then userThreshold = minQuota end

local tokenPending = 0
local prospectiveToken = 0
local tokenThreshold = 0
if token ~= '0' then
  tokenPending = tonumber(redis.call('HGET', KEYS[3], 'token:' .. token)) or 0
  prospectiveToken = tokenPending + amount
  tokenThreshold = math.floor((prospectiveToken * factor + 999) / 1000)
  if tokenThreshold < minQuota then tokenThreshold = minQuota end
end

if userQuota <= userThreshold or (token ~= '0' and tokenQuota <= tokenThreshold) then
  return {0, userThreshold, tokenThreshold, prospectiveUser, prospectiveToken}
end

redis.call('HSET', KEYS[2], id .. ':amount', amount, id .. ':token', token)
redis.call('HINCRBY', KEYS[3], 'user', amount)
if token ~= '0' then redis.call('HINCRBY', KEYS[3], 'token:' .. token, amount) end
redis.call('ZADD', KEYS[1], now + lease, id)
redis.call('PEXPIRE', KEYS[1], lease * 2)
redis.call('PEXPIRE', KEYS[2], lease * 2)
redis.call('PEXPIRE', KEYS[3], lease * 2)
return {1, userThreshold, tokenThreshold, prospectiveUser, prospectiveToken}
`)

var dynamicTrustResizeScript = redis.NewScript(`
local now = tonumber(ARGV[1])
local lease = tonumber(ARGV[2])
local id = ARGV[3]
local target = tonumber(ARGV[4])
local minQuota = tonumber(ARGV[5])
local factor = tonumber(ARGV[6])
local old = tonumber(redis.call('HGET', KEYS[2], id .. ':amount'))
if not old then return {-1, 0, 0, 0, 0} end
local token = redis.call('HGET', KEYS[2], id .. ':token') or '0'
if target <= old then
  redis.call('ZADD', KEYS[1], now + lease, id)
  return {1, 0, 0, tonumber(redis.call('HGET', KEYS[3], 'user')) or 0,
    tonumber(redis.call('HGET', KEYS[3], 'token:' .. token)) or 0}
end
local userQuota = tonumber(redis.call('HGET', KEYS[4], 'Quota'))
if not userQuota then return {-2, 0, 0, 0, 0} end
local tokenQuota = 0
if token ~= '0' then
  tokenQuota = tonumber(redis.call('HGET', KEYS[5], 'RemainQuota'))
  if not tokenQuota then return {-3, 0, 0, 0, 0} end
end
local delta = target - old
local prospectiveUser = (tonumber(redis.call('HGET', KEYS[3], 'user')) or 0) + delta
local userThreshold = math.floor((prospectiveUser * factor + 999) / 1000)
if userThreshold < minQuota then userThreshold = minQuota end
local prospectiveToken = 0
local tokenThreshold = 0
if token ~= '0' then
  prospectiveToken = (tonumber(redis.call('HGET', KEYS[3], 'token:' .. token)) or 0) + delta
  tokenThreshold = math.floor((prospectiveToken * factor + 999) / 1000)
  if tokenThreshold < minQuota then tokenThreshold = minQuota end
end
if userQuota <= userThreshold or (token ~= '0' and tokenQuota <= tokenThreshold) then
  return {0, userThreshold, tokenThreshold, prospectiveUser, prospectiveToken}
end

redis.call('HSET', KEYS[2], id .. ':amount', target)
redis.call('HINCRBY', KEYS[3], 'user', delta)
if token ~= '0' then redis.call('HINCRBY', KEYS[3], 'token:' .. token, delta) end
redis.call('ZADD', KEYS[1], now + lease, id)
redis.call('PEXPIRE', KEYS[1], lease * 2)
redis.call('PEXPIRE', KEYS[2], lease * 2)
redis.call('PEXPIRE', KEYS[3], lease * 2)
return {1, userThreshold, tokenThreshold, prospectiveUser, prospectiveToken}
`)

var dynamicTrustRefreshScript = redis.NewScript(`
local id = ARGV[1]
local expiresAt = tonumber(ARGV[2])
local lease = tonumber(ARGV[3])
if not redis.call('HEXISTS', KEYS[2], id .. ':amount') then return 0 end
redis.call('ZADD', KEYS[1], expiresAt, id)
redis.call('PEXPIRE', KEYS[1], lease * 2)
redis.call('PEXPIRE', KEYS[2], lease * 2)
redis.call('PEXPIRE', KEYS[3], lease * 2)
return 1
`)

var dynamicTrustSettleScript = redis.NewScript(`
local id = ARGV[1]
local actual = tonumber(ARGV[2])
local expiresAt = tonumber(ARGV[3])
local ttl = tonumber(ARGV[4])
local old = tonumber(redis.call('HGET', KEYS[2], id .. ':amount'))
if not old then return 0 end
local token = redis.call('HGET', KEYS[2], id .. ':token') or '0'
local delta = actual - old
redis.call('HINCRBY', KEYS[3], 'user', delta)
if token ~= '0' then redis.call('HINCRBY', KEYS[3], 'token:' .. token, delta) end
if actual <= 0 then
  redis.call('HDEL', KEYS[2], id .. ':amount', id .. ':token')
  redis.call('ZREM', KEYS[1], id)
else
  redis.call('HSET', KEYS[2], id .. ':amount', actual)
  redis.call('ZADD', KEYS[1], expiresAt, id)
  redis.call('PEXPIRE', KEYS[1], ttl)
  redis.call('PEXPIRE', KEYS[2], ttl)
  redis.call('PEXPIRE', KEYS[3], ttl)
end
return 1
`)

var dynamicTrustReleaseScript = redis.NewScript(`
local id = ARGV[1]
local old = tonumber(redis.call('HGET', KEYS[2], id .. ':amount'))
if not old then return 0 end
local token = redis.call('HGET', KEYS[2], id .. ':token') or '0'
redis.call('HINCRBY', KEYS[3], 'user', -old)
if token ~= '0' then redis.call('HINCRBY', KEYS[3], 'token:' .. token, -old) end
redis.call('HDEL', KEYS[2], id .. ':amount', id .. ':token')
redis.call('ZREM', KEYS[1], id)
return 1
`)

func (s *redisDynamicTrustStore) Acquire(ctx context.Context, params dynamicTrustAcquireParams) (dynamicTrustDecision, error) {
	if s == nil || s.client == nil {
		return dynamicTrustDecision{}, errors.New("redis client is unavailable")
	}
	tokenID := params.TokenID
	if params.TokenUnlimited {
		tokenID = 0
	}
	result, err := s.runDecisionScript(ctx, dynamicTrustAcquireScript,
		dynamicTrustDecisionKeys(params.UserID, params.TokenKey, params.TokenUnlimited),
		time.Now().UnixMilli(), dynamicTrustLease.Milliseconds(), params.RequestID, params.Amount,
		tokenID, params.MinQuota, params.FactorMillis)
	if err != nil {
		return dynamicTrustDecision{}, err
	}
	return result, nil
}

func (s *redisDynamicTrustStore) Resize(ctx context.Context, reservation *dynamicTrustReservation, targetQuota int) (dynamicTrustDecision, error) {
	if reservation == nil {
		return dynamicTrustDecision{}, errors.New("dynamic trust reservation is nil")
	}
	decision, err := s.runDecisionScript(ctx, dynamicTrustResizeScript,
		dynamicTrustDecisionKeys(reservation.userID, reservation.tokenKey, reservation.tokenUnlimited),
		time.Now().UnixMilli(), dynamicTrustLease.Milliseconds(), reservation.requestID, targetQuota,
		reservation.minQuota, reservation.factorMillis)
	if err != nil {
		return dynamicTrustDecision{}, err
	}
	if decision.Trusted {
		reservation.amount = targetQuota
	}
	return decision, nil
}

func (s *redisDynamicTrustStore) Refresh(ctx context.Context, reservation *dynamicTrustReservation) error {
	if reservation == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(ctx, dynamicTrustRedisTimeout)
	defer cancel()
	result, err := dynamicTrustRefreshScript.Run(ctx, s.client, dynamicTrustKeys(reservation.userID),
		reservation.requestID, time.Now().Add(dynamicTrustLease).UnixMilli(), dynamicTrustLease.Milliseconds()).Int()
	if err != nil {
		return err
	}
	if result != 1 {
		return errors.New("dynamic trust reservation no longer exists")
	}
	return nil
}

func (s *redisDynamicTrustStore) Settle(ctx context.Context, reservation *dynamicTrustReservation, actualQuota int, grace time.Duration) error {
	if reservation == nil {
		return nil
	}
	if actualQuota < 0 {
		return errors.New("actual quota cannot be negative")
	}
	ctx, cancel := context.WithTimeout(ctx, dynamicTrustRedisTimeout)
	defer cancel()
	ttl := grace * 2
	if ttl < dynamicTrustLease*2 {
		ttl = dynamicTrustLease * 2
	}
	result, err := dynamicTrustSettleScript.Run(ctx, s.client, dynamicTrustKeys(reservation.userID),
		reservation.requestID, actualQuota, time.Now().Add(grace).UnixMilli(), ttl.Milliseconds()).Int()
	if err != nil {
		return err
	}
	if result != 1 {
		return errors.New("dynamic trust reservation no longer exists")
	}
	return nil
}

func (s *redisDynamicTrustStore) Release(ctx context.Context, reservation *dynamicTrustReservation) error {
	if reservation == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(ctx, dynamicTrustRedisTimeout)
	defer cancel()
	_, err := dynamicTrustReleaseScript.Run(ctx, s.client, dynamicTrustKeys(reservation.userID), reservation.requestID).Result()
	return err
}

func (s *redisDynamicTrustStore) runDecisionScript(ctx context.Context, script *redis.Script, keys []string, args ...interface{}) (dynamicTrustDecision, error) {
	ctx, cancel := context.WithTimeout(ctx, dynamicTrustRedisTimeout)
	defer cancel()
	values, err := script.Run(ctx, s.client, keys, args...).Slice()
	if err != nil {
		return dynamicTrustDecision{}, err
	}
	if len(values) != 5 {
		return dynamicTrustDecision{}, fmt.Errorf("unexpected dynamic trust result length: %d", len(values))
	}
	parsed := make([]int64, len(values))
	for i, value := range values {
		switch v := value.(type) {
		case int64:
			parsed[i] = v
		case string:
			n, parseErr := strconv.ParseInt(v, 10, 64)
			if parseErr != nil {
				return dynamicTrustDecision{}, parseErr
			}
			parsed[i] = n
		default:
			return dynamicTrustDecision{}, fmt.Errorf("unexpected dynamic trust result type: %T", value)
		}
	}
	switch parsed[0] {
	case -1:
		return dynamicTrustDecision{}, errors.New("dynamic trust reservation no longer exists")
	case -2:
		return dynamicTrustDecision{}, errors.New("dynamic trust user quota cache is unavailable")
	case -3:
		return dynamicTrustDecision{}, errors.New("dynamic trust token quota cache is unavailable")
	default:
		if parsed[0] < 0 {
			return dynamicTrustDecision{}, errors.New("dynamic trust returned an invalid state")
		}
	}
	return dynamicTrustDecision{
		Trusted:        parsed[0] > 0,
		UserThreshold:  int(parsed[1]),
		TokenThreshold: int(parsed[2]),
		UserPending:    int(parsed[3]),
		TokenPending:   int(parsed[4]),
	}, nil
}
