package common

import "math"

const (
	defaultTrustQuotaMinUSD        = 10.0
	defaultTrustQuotaDynamicFactor = 1.5
)

func initTrustQuotaConfig() {
	minUSD := GetEnvOrDefaultFloat64("TRUST_QUOTA_MIN_USD", defaultTrustQuotaMinUSD)
	if math.IsNaN(minUSD) || math.IsInf(minUSD, 0) || minUSD < 0 {
		SysError("TRUST_QUOTA_MIN_USD must be a finite non-negative number, using default value: 10")
		minUSD = defaultTrustQuotaMinUSD
	}
	if _, err := QuotaFromFloatStrict(minUSD * QuotaPerUnit); err != nil {
		SysError("TRUST_QUOTA_MIN_USD is too large, using default value: 10")
		minUSD = defaultTrustQuotaMinUSD
	}

	factor := GetEnvOrDefaultFloat64("TRUST_QUOTA_DYNAMIC_FACTOR", defaultTrustQuotaDynamicFactor)
	if math.IsNaN(factor) || math.IsInf(factor, 0) || factor < 1 || factor > 10 {
		SysError("TRUST_QUOTA_DYNAMIC_FACTOR must be between 1 and 10, using default value: 1.5")
		factor = defaultTrustQuotaDynamicFactor
	}

	TrustQuotaMinUSD = minUSD
	TrustQuotaDynamicEnabled = GetEnvOrDefaultBool("TRUST_QUOTA_DYNAMIC_ENABLED", false)
	TrustQuotaDynamicFactor = factor
}

func GetTrustQuota() int {
	quota, err := QuotaFromFloatStrict(TrustQuotaMinUSD * QuotaPerUnit)
	if err != nil {
		return QuotaFromFloat(defaultTrustQuotaMinUSD * QuotaPerUnit)
	}
	return quota
}

func GetTrustQuotaDynamicFactorMillis() int64 {
	return int64(math.Round(TrustQuotaDynamicFactor * 1000))
}
