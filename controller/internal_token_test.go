package controller

import (
	"bytes"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/constant"
	"github.com/QuantumNous/new-api/middleware"
	"github.com/QuantumNous/new-api/model"
	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/cookie"
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

type internalResolveResponse struct {
	TokenID        int    `json:"tokenId"`
	UserID         int    `json:"userId"`
	Name           string `json:"name"`
	Group          string `json:"group"`
	Status         int    `json:"status"`
	ExpiredTime    int64  `json:"expiredTime"`
	UnlimitedQuota bool   `json:"unlimitedQuota"`
}

func setupInternalTokenControllerTestDB(t *testing.T) *gorm.DB {
	t.Helper()

	db := setupTokenControllerTestDB(t)
	if err := db.AutoMigrate(&model.User{}); err != nil {
		t.Fatalf("failed to migrate user table: %v", err)
	}
	return db
}

func seedInternalUser(t *testing.T, db *gorm.DB, userID int, role int, group string, accessToken string) *model.User {
	t.Helper()

	token := accessToken
	user := &model.User{
		Id:          userID,
		Username:    fmt.Sprintf("user_%d", userID),
		Password:    "password123",
		DisplayName: fmt.Sprintf("User %d", userID),
		Role:        role,
		Status:      common.UserStatusEnabled,
		Email:       fmt.Sprintf("user_%d@example.com", userID),
		Group:       group,
		AccessToken: &token,
	}
	if err := db.Create(user).Error; err != nil {
		t.Fatalf("failed to create user: %v", err)
	}
	return user
}

func seedInternalLookupToken(t *testing.T, db *gorm.DB, userID int, name string, rawKey string, group string, unlimitedQuota bool) *model.Token {
	t.Helper()

	token := &model.Token{
		UserId:         userID,
		Name:           name,
		Key:            rawKey,
		Status:         common.TokenStatusEnabled,
		CreatedTime:    1,
		AccessedTime:   1,
		ExpiredTime:    -1,
		RemainQuota:    100,
		UnlimitedQuota: unlimitedQuota,
		Group:          group,
	}
	if err := db.Create(token).Error; err != nil {
		t.Fatalf("failed to create token: %v", err)
	}
	return token
}

func newInternalResolveRouter() *gin.Engine {
	router := gin.New()
	store := cookie.NewStore([]byte("test-session-secret"))
	router.Use(sessions.Sessions("test-session", store))

	apiRouter := router.Group("/api")
	internalAdminRoute := apiRouter.Group("/internal/admin")
	internalAdminRoute.Use(middleware.AdminAuth())
	internalAdminRoute.Use(middleware.InternalAdminSecretAuth())
	internalAdminRoute.POST("/token/resolve", ResolveTokenByKey)

	return router
}

func newInternalResolveRequest(t *testing.T, key string) *bytes.Reader {
	t.Helper()

	payload, err := common.Marshal(map[string]any{"key": key})
	if err != nil {
		t.Fatalf("failed to marshal request body: %v", err)
	}
	return bytes.NewReader(payload)
}

func TestResolveTokenByKeySuccess(t *testing.T) {
	db := setupInternalTokenControllerTestDB(t)
	seedInternalUser(t, db, 4, common.RoleCommonUser, "default", "user-access-token")
	token := seedInternalLookupToken(t, db, 4, "自动发货-3-24-V6rhKT", "resolve-key-123", "default", false)

	ctx, recorder := newAuthenticatedContext(t, http.MethodPost, "/api/internal/admin/token/resolve", map[string]any{"key": "sk-resolve-key-123"}, 1)
	ResolveTokenByKey(ctx)

	response := decodeAPIResponse(t, recorder)
	if !response.Success {
		t.Fatalf("expected success response, got message: %s", response.Message)
	}

	var resolved internalResolveResponse
	if err := common.Unmarshal(response.Data, &resolved); err != nil {
		t.Fatalf("failed to decode resolve response: %v", err)
	}
	if resolved.TokenID != token.Id || resolved.UserID != token.UserId {
		t.Fatalf("unexpected token identity: %+v", resolved)
	}
	if resolved.Name != token.Name || resolved.Group != token.Group {
		t.Fatalf("unexpected token details: %+v", resolved)
	}
	if resolved.Status != token.Status || resolved.ExpiredTime != token.ExpiredTime || resolved.UnlimitedQuota != token.UnlimitedQuota {
		t.Fatalf("unexpected token flags: %+v", resolved)
	}
	if strings.Contains(recorder.Body.String(), token.Key) {
		t.Fatalf("resolve response leaked raw token key: %s", recorder.Body.String())
	}
}

func TestResolveTokenByKeyRejectsKeyWithoutPrefix(t *testing.T) {
	setupInternalTokenControllerTestDB(t)

	ctx, recorder := newAuthenticatedContext(t, http.MethodPost, "/api/internal/admin/token/resolve", map[string]any{"key": "resolve-key-123"}, 1)
	ResolveTokenByKey(ctx)

	response := decodeAPIResponse(t, recorder)
	if response.Success {
		t.Fatalf("expected invalid key format failure")
	}
	if response.Message != "invalid key format" {
		t.Fatalf("expected invalid key format message, got %q", response.Message)
	}
}

func TestResolveTokenByKeyReturnsNotFound(t *testing.T) {
	setupInternalTokenControllerTestDB(t)

	ctx, recorder := newAuthenticatedContext(t, http.MethodPost, "/api/internal/admin/token/resolve", map[string]any{"key": "sk-missing-key"}, 1)
	ResolveTokenByKey(ctx)

	response := decodeAPIResponse(t, recorder)
	if response.Success {
		t.Fatalf("expected missing token failure")
	}
	if response.Message != "token not found" {
		t.Fatalf("expected token not found message, got %q", response.Message)
	}
}

func TestResolveTokenByKeyFallsBackToUserGroup(t *testing.T) {
	db := setupInternalTokenControllerTestDB(t)
	seedInternalUser(t, db, 9, common.RoleCommonUser, "vip", "vip-access-token")
	seedInternalLookupToken(t, db, 9, "group-fallback-token", "fallback-key-123", "", true)

	ctx, recorder := newAuthenticatedContext(t, http.MethodPost, "/api/internal/admin/token/resolve", map[string]any{"key": "sk-fallback-key-123"}, 1)
	ResolveTokenByKey(ctx)

	response := decodeAPIResponse(t, recorder)
	if !response.Success {
		t.Fatalf("expected success response, got message: %s", response.Message)
	}

	var resolved internalResolveResponse
	if err := common.Unmarshal(response.Data, &resolved); err != nil {
		t.Fatalf("failed to decode fallback response: %v", err)
	}
	if resolved.Group != "vip" {
		t.Fatalf("expected fallback group vip, got %q", resolved.Group)
	}
}

func TestInternalAdminResolveRouteRequiresSecretHeader(t *testing.T) {
	db := setupInternalTokenControllerTestDB(t)
	seedInternalUser(t, db, 1, common.RoleAdminUser, "default", "admin-access-token")
	seedInternalLookupToken(t, db, 4, "route-token", "route-key-123", "default", false)

	originalSecret := constant.InternalAdminSecret
	constant.InternalAdminSecret = "internal-secret"
	t.Cleanup(func() {
		constant.InternalAdminSecret = originalSecret
	})

	router := newInternalResolveRouter()
	request := httptest.NewRequest(http.MethodPost, "/api/internal/admin/token/resolve", newInternalResolveRequest(t, "sk-route-key-123"))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Authorization", "Bearer admin-access-token")
	request.Header.Set("New-Api-User", "1")

	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusForbidden {
		t.Fatalf("expected 403 when secret header missing, got %d", recorder.Code)
	}

	response := decodeAPIResponse(t, recorder)
	if response.Success || response.Message != "forbidden" {
		t.Fatalf("expected forbidden response, got %+v", response)
	}
}

func TestInternalAdminResolveRouteAcceptsAdminWithSecret(t *testing.T) {
	db := setupInternalTokenControllerTestDB(t)
	seedInternalUser(t, db, 1, common.RoleAdminUser, "default", "admin-access-token")
	token := seedInternalLookupToken(t, db, 4, "route-token", "route-key-456", "default", false)

	originalSecret := constant.InternalAdminSecret
	constant.InternalAdminSecret = "internal-secret"
	t.Cleanup(func() {
		constant.InternalAdminSecret = originalSecret
	})

	router := newInternalResolveRouter()
	request := httptest.NewRequest(http.MethodPost, "/api/internal/admin/token/resolve", newInternalResolveRequest(t, "sk-route-key-456"))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Authorization", "Bearer admin-access-token")
	request.Header.Set("New-Api-User", "1")
	request.Header.Set("X-Internal-Admin-Secret", "internal-secret")

	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("expected 200 for authorized request, got %d", recorder.Code)
	}

	response := decodeAPIResponse(t, recorder)
	if !response.Success {
		t.Fatalf("expected success response, got %+v", response)
	}

	var resolved internalResolveResponse
	if err := common.Unmarshal(response.Data, &resolved); err != nil {
		t.Fatalf("failed to decode route resolve response: %v", err)
	}
	if resolved.TokenID != token.Id || resolved.UserID != token.UserId {
		t.Fatalf("unexpected route resolve response: %+v", resolved)
	}
}

func TestInternalAdminResolveRouteRejectsWhenSecretNotConfigured(t *testing.T) {
	db := setupInternalTokenControllerTestDB(t)
	seedInternalUser(t, db, 1, common.RoleAdminUser, "default", "admin-access-token")
	seedInternalLookupToken(t, db, 4, "route-token", "route-key-config", "default", false)

	originalSecret := constant.InternalAdminSecret
	constant.InternalAdminSecret = ""
	t.Cleanup(func() {
		constant.InternalAdminSecret = originalSecret
	})

	router := newInternalResolveRouter()
	request := httptest.NewRequest(http.MethodPost, "/api/internal/admin/token/resolve", newInternalResolveRequest(t, "sk-route-key-config"))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Authorization", "Bearer admin-access-token")
	request.Header.Set("New-Api-User", "1")
	request.Header.Set("X-Internal-Admin-Secret", "unused")

	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503 when internal secret is missing, got %d", recorder.Code)
	}

	response := decodeAPIResponse(t, recorder)
	if response.Success || response.Message != "internal admin secret not configured" {
		t.Fatalf("expected explicit config error, got %+v", response)
	}
}

func TestInternalAdminResolveRouteRejectsNonAdminAccessToken(t *testing.T) {
	db := setupInternalTokenControllerTestDB(t)
	seedInternalUser(t, db, 2, common.RoleCommonUser, "default", "common-access-token")
	seedInternalLookupToken(t, db, 4, "route-token", "route-key-789", "default", false)

	originalSecret := constant.InternalAdminSecret
	constant.InternalAdminSecret = "internal-secret"
	t.Cleanup(func() {
		constant.InternalAdminSecret = originalSecret
	})

	router := newInternalResolveRouter()
	request := httptest.NewRequest(http.MethodPost, "/api/internal/admin/token/resolve", newInternalResolveRequest(t, "sk-route-key-789"))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Authorization", "Bearer common-access-token")
	request.Header.Set("New-Api-User", "2")
	request.Header.Set("X-Internal-Admin-Secret", "internal-secret")

	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("expected existing AdminAuth semantics to keep 200 status, got %d", recorder.Code)
	}

	response := decodeAPIResponse(t, recorder)
	if response.Success {
		t.Fatalf("expected non-admin request to fail")
	}
	if !strings.Contains(response.Message, "权限不足") {
		t.Fatalf("expected permission denied message, got %q", response.Message)
	}
}
