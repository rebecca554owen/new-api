package common

import "fmt"

// DynamicTrustRedisKeys returns the shared Redis keys used to track trusted
// in-flight billing exposure for one user.
func DynamicTrustRedisKeys(userID int) []string {
	base := fmt.Sprintf("trust:pending:{%d}", userID)
	return []string{base + ":expires", base + ":requests", base + ":totals"}
}
