package common

import (
	"math"
	"os"
)

const defaultPreConsumeMaxTokens = 8192

func initPreConsumeConfig() {
	PreConsumeStrictEnabled = GetEnvOrDefaultBool("PRE_CONSUME_STRICT_ENABLED", false)
	PreConsumeAtomicEnabled = GetEnvOrDefaultBool("PRE_CONSUME_ATOMIC_ENABLED", false)

	maxTokens := GetEnvOrDefault("PRE_CONSUME_DEFAULT_MAX_TOKENS", defaultPreConsumeMaxTokens)
	if maxTokens <= 0 || int64(maxTokens) > int64(math.MaxInt32/2) {
		SysError("PRE_CONSUME_DEFAULT_MAX_TOKENS must be between 1 and 1073741823, using default value: 8192")
		maxTokens = defaultPreConsumeMaxTokens
	}
	PreConsumeDefaultMaxTokens = maxTokens

	if PreConsumeAtomicEnabled && os.Getenv("REDIS_CONN_STRING") == "" {
		SysError("PRE_CONSUME_ATOMIC_ENABLED requires Redis; paid wallet requests will be rejected until Redis is available")
	}
	if PreConsumeAtomicEnabled && os.Getenv("BATCH_UPDATE_ENABLED") != "true" {
		SysError("PRE_CONSUME_ATOMIC_ENABLED requires BATCH_UPDATE_ENABLED=true; paid wallet requests will be rejected until batch updates are enabled")
	}
	if PreConsumeStrictEnabled && !PreConsumeAtomicEnabled {
		SysError("PRE_CONSUME_STRICT_ENABLED is enabled without PRE_CONSUME_ATOMIC_ENABLED; concurrent quota oversubscription remains possible")
	}
}
