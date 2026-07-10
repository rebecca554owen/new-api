package controller

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/middleware"
	"github.com/QuantumNous/new-api/model"
	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/cookie"
	"github.com/gin-gonic/gin"
)

func newTokenCreationSecurityRouter() *gin.Engine {
	router := gin.New()
	store := cookie.NewStore([]byte("token-creation-security-test"))
	router.Use(sessions.Sessions("test-session", store))

	tokenRoute := router.Group("/api/token")
	tokenRoute.Use(middleware.UserAuth())
	tokenRoute.POST("/", AddToken)

	return router
}

func TestAddTokenAllowsSelfCreate(t *testing.T) {
	db := setupInternalTokenControllerTestDB(t)
	seedInternalUser(t, db, 4, common.RoleCommonUser, "default", "user-access-token")

	body := map[string]any{
		"name":                 "self-created-token",
		"user_id":              4,
		"expired_time":         -1,
		"remain_quota":         0,
		"unlimited_quota":      false,
		"model_limits_enabled": false,
		"model_limits":         "",
		"group":                "default",
		"cross_group_retry":    false,
	}

	ctx, recorder := newAuthenticatedContext(t, http.MethodPost, "/api/token/", body, 4)
	ctx.Set("role", common.RoleCommonUser)
	AddToken(ctx)

	response := decodeAPIResponse(t, recorder)
	if !response.Success {
		t.Fatalf("expected self token creation to succeed, got message: %s", response.Message)
	}

	var created tokenCreateResponse
	if err := common.Unmarshal(response.Data, &created); err != nil {
		t.Fatalf("failed to decode create token response: %v", err)
	}
	if created.UserID != 4 || !strings.HasPrefix(created.Value, "sk-") {
		t.Fatalf("expected a plaintext self-owned token, got %+v", created)
	}
}

func TestAddTokenRejectsAdminProxyCreateForPeerOrRootUser(t *testing.T) {
	db := setupInternalTokenControllerTestDB(t)
	seedInternalUser(t, db, 1, common.RoleAdminUser, "default", "admin-access-token")
	seedInternalUser(t, db, 2, common.RoleAdminUser, "default", "peer-admin-access-token")
	seedInternalUser(t, db, 3, common.RoleRootUser, "default", "root-access-token")

	tests := []struct {
		name         string
		targetUserID int
	}{
		{name: "peer administrator", targetUserID: 2},
		{name: "root user", targetUserID: 3},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			body := map[string]any{
				"name":                 "unauthorized-proxy-token",
				"user_id":              test.targetUserID,
				"expired_time":         -1,
				"remain_quota":         0,
				"unlimited_quota":      false,
				"model_limits_enabled": false,
				"model_limits":         "",
				"group":                "default",
				"cross_group_retry":    false,
			}

			ctx, recorder := newAuthenticatedContext(t, http.MethodPost, "/api/token/", body, 1)
			ctx.Set("role", common.RoleAdminUser)
			AddToken(ctx)

			response := decodeAPIResponse(t, recorder)
			if response.Success {
				t.Fatalf("expected delegated token creation for %s to fail", test.name)
			}
			if response.Message != "无权为其他用户创建令牌" {
				t.Fatalf("expected authorization error, got %q", response.Message)
			}
			if strings.Contains(recorder.Body.String(), "\"value\"") || strings.Contains(recorder.Body.String(), "sk-") {
				t.Fatalf("denied response disclosed token material: %s", recorder.Body.String())
			}

			var tokenCount int64
			if err := db.Model(&model.Token{}).Where("user_id = ?", test.targetUserID).Count(&tokenCount).Error; err != nil {
				t.Fatalf("failed to count target tokens: %v", err)
			}
			if tokenCount != 0 {
				t.Fatalf("expected no token for denied target, found %d", tokenCount)
			}
		})
	}
}

func TestAddTokenUserAuthRouteEnforcesAdminDelegationHierarchy(t *testing.T) {
	db := setupInternalTokenControllerTestDB(t)
	seedInternalUser(t, db, 1, common.RoleAdminUser, "default", "admin-access-token")
	seedInternalUser(t, db, 3, common.RoleRootUser, "default", "root-access-token")
	seedInternalUser(t, db, 4, common.RoleCommonUser, "default", "user-access-token")
	router := newTokenCreationSecurityRouter()

	tests := []struct {
		name         string
		targetUserID int
		wantSuccess  bool
	}{
		{name: "lower role", targetUserID: 4, wantSuccess: true},
		{name: "higher role", targetUserID: 3, wantSuccess: false},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			body, err := common.Marshal(map[string]any{
				"name":                 "route-delegation-" + strconv.Itoa(test.targetUserID),
				"user_id":              test.targetUserID,
				"expired_time":         -1,
				"remain_quota":         0,
				"unlimited_quota":      false,
				"model_limits_enabled": false,
				"model_limits":         "",
				"group":                "default",
				"cross_group_retry":    false,
			})
			if err != nil {
				t.Fatalf("failed to marshal request: %v", err)
			}

			request := httptest.NewRequest(http.MethodPost, "/api/token/", bytes.NewReader(body))
			request.Header.Set("Content-Type", "application/json")
			request.Header.Set("Authorization", "Bearer admin-access-token")
			request.Header.Set("New-Api-User", "1")
			recorder := httptest.NewRecorder()
			router.ServeHTTP(recorder, request)

			response := decodeAPIResponse(t, recorder)
			if response.Success != test.wantSuccess {
				t.Fatalf("expected success=%t, got success=%t message=%q", test.wantSuccess, response.Success, response.Message)
			}
			if !test.wantSuccess {
				if response.Message != "无权为其他用户创建令牌" {
					t.Fatalf("expected authorization error, got %q", response.Message)
				}
				if strings.Contains(recorder.Body.String(), "\"value\"") || strings.Contains(recorder.Body.String(), "sk-") {
					t.Fatalf("denied response disclosed token material: %s", recorder.Body.String())
				}
			}

			var tokenCount int64
			if err := db.Model(&model.Token{}).Where("user_id = ?", test.targetUserID).Count(&tokenCount).Error; err != nil {
				t.Fatalf("failed to count target tokens: %v", err)
			}
			if test.wantSuccess && tokenCount != 1 {
				t.Fatalf("expected one delegated token for lower-role target, found %d", tokenCount)
			}
			if !test.wantSuccess && tokenCount != 0 {
				t.Fatalf("expected no token for denied target, found %d", tokenCount)
			}
		})
	}
}
