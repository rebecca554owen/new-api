package common

import (
	"math"
	"testing"

	"github.com/stretchr/testify/assert"
)

func preserveTrustQuotaConfig(t *testing.T) {
	t.Helper()
	minUSD := TrustQuotaMinUSD
	dynamicEnabled := TrustQuotaDynamicEnabled
	factor := TrustQuotaDynamicFactor
	t.Cleanup(func() {
		TrustQuotaMinUSD = minUSD
		TrustQuotaDynamicEnabled = dynamicEnabled
		TrustQuotaDynamicFactor = factor
	})
}

func TestTrustQuotaConfigDefaults(t *testing.T) {
	preserveTrustQuotaConfig(t)
	t.Setenv("TRUST_QUOTA_MIN_USD", "")
	t.Setenv("TRUST_QUOTA_DYNAMIC_ENABLED", "")
	t.Setenv("TRUST_QUOTA_DYNAMIC_FACTOR", "")

	initTrustQuotaConfig()

	assert.Equal(t, 10.0, TrustQuotaMinUSD)
	assert.False(t, TrustQuotaDynamicEnabled)
	assert.Equal(t, 1.5, TrustQuotaDynamicFactor)
	assert.Equal(t, QuotaFromFloat(10*QuotaPerUnit), GetTrustQuota())
	assert.Equal(t, int64(1500), GetTrustQuotaDynamicFactorMillis())
}

func TestTrustQuotaConfigCustomValues(t *testing.T) {
	preserveTrustQuotaConfig(t)
	t.Setenv("TRUST_QUOTA_MIN_USD", "50.5")
	t.Setenv("TRUST_QUOTA_DYNAMIC_ENABLED", "true")
	t.Setenv("TRUST_QUOTA_DYNAMIC_FACTOR", "2.25")

	initTrustQuotaConfig()

	assert.Equal(t, 50.5, TrustQuotaMinUSD)
	assert.True(t, TrustQuotaDynamicEnabled)
	assert.Equal(t, 2.25, TrustQuotaDynamicFactor)
	assert.Equal(t, QuotaFromFloat(50.5*QuotaPerUnit), GetTrustQuota())
	assert.Equal(t, int64(2250), GetTrustQuotaDynamicFactorMillis())
}

func TestTrustQuotaConfigRejectsInvalidValues(t *testing.T) {
	preserveTrustQuotaConfig(t)
	t.Setenv("TRUST_QUOTA_MIN_USD", "-1")
	t.Setenv("TRUST_QUOTA_DYNAMIC_FACTOR", "11")

	initTrustQuotaConfig()

	assert.Equal(t, 10.0, TrustQuotaMinUSD)
	assert.Equal(t, 1.5, TrustQuotaDynamicFactor)

	t.Setenv("TRUST_QUOTA_MIN_USD", "NaN")
	t.Setenv("TRUST_QUOTA_DYNAMIC_FACTOR", "Inf")
	initTrustQuotaConfig()
	assert.False(t, math.IsNaN(TrustQuotaMinUSD))
	assert.False(t, math.IsInf(TrustQuotaDynamicFactor, 0))
}

func TestZeroTrustQuotaDisablesTrustThreshold(t *testing.T) {
	preserveTrustQuotaConfig(t)
	t.Setenv("TRUST_QUOTA_MIN_USD", "0")

	initTrustQuotaConfig()

	assert.Zero(t, GetTrustQuota())
}
