package common

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestPreConsumeConfigDefaultsAndValidation(t *testing.T) {
	oldStrict := PreConsumeStrictEnabled
	oldAtomic := PreConsumeAtomicEnabled
	oldMaxTokens := PreConsumeDefaultMaxTokens
	t.Cleanup(func() {
		PreConsumeStrictEnabled = oldStrict
		PreConsumeAtomicEnabled = oldAtomic
		PreConsumeDefaultMaxTokens = oldMaxTokens
	})

	t.Setenv("PRE_CONSUME_STRICT_ENABLED", "true")
	t.Setenv("PRE_CONSUME_ATOMIC_ENABLED", "true")
	t.Setenv("PRE_CONSUME_DEFAULT_MAX_TOKENS", "4096")
	initPreConsumeConfig()
	assert.True(t, PreConsumeStrictEnabled)
	assert.True(t, PreConsumeAtomicEnabled)
	assert.Equal(t, 4096, PreConsumeDefaultMaxTokens)

	t.Setenv("PRE_CONSUME_DEFAULT_MAX_TOKENS", "0")
	initPreConsumeConfig()
	assert.Equal(t, 8192, PreConsumeDefaultMaxTokens)
}
