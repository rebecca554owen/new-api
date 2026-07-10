package controller

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/model"
	"github.com/gin-gonic/gin"
)

type adminTokenKeysResponse struct {
	Keys map[int]string `json:"keys"`
}

func TestAdminGetTokenKeyHandlerRequiresRootRole(t *testing.T) {
	db := setupInternalTokenControllerTestDB(t)
	seedInternalUser(t, db, 4, common.RoleCommonUser, "default", "user4-access-token")
	token := seedInternalLookupToken(t, db, 4, "foreign-token", "foreign-key-secret", "default", false)

	adminCtx, adminRecorder := newAuthenticatedContext(t, http.MethodPost, "/api/token/admin/"+strconv.Itoa(token.Id)+"/key", nil, 1)
	adminCtx.Set("role", common.RoleAdminUser)
	adminCtx.Params = gin.Params{{Key: "id", Value: strconv.Itoa(token.Id)}}
	AdminGetTokenKey(adminCtx)

	adminResponse := decodeAPIResponse(t, adminRecorder)
	if adminResponse.Success {
		t.Fatalf("expected role-10 administrator key reveal to fail")
	}
	if strings.Contains(adminRecorder.Body.String(), token.Key) {
		t.Fatalf("role-10 administrator response leaked raw token key: %s", adminRecorder.Body.String())
	}

	rootCtx, rootRecorder := newAuthenticatedContext(t, http.MethodPost, "/api/token/admin/"+strconv.Itoa(token.Id)+"/key", nil, 2)
	rootCtx.Set("role", common.RoleRootUser)
	rootCtx.Params = gin.Params{{Key: "id", Value: strconv.Itoa(token.Id)}}
	AdminGetTokenKey(rootCtx)

	rootResponse := decodeAPIResponse(t, rootRecorder)
	if !rootResponse.Success {
		t.Fatalf("expected root key reveal to succeed, got message: %s", rootResponse.Message)
	}
	var keyData tokenKeyResponse
	if err := common.Unmarshal(rootResponse.Data, &keyData); err != nil {
		t.Fatalf("failed to decode root token key response: %v", err)
	}
	if keyData.Key != token.GetFullKey() {
		t.Fatalf("expected root to receive full key %q, got %q", token.GetFullKey(), keyData.Key)
	}
}

func TestAdminGetTokenKeysBatchHandlerRequiresRootRole(t *testing.T) {
	db := setupInternalTokenControllerTestDB(t)
	seedInternalUser(t, db, 2, common.RoleRootUser, "default", "root-access-token")
	seedInternalUser(t, db, 4, common.RoleCommonUser, "default", "user4-access-token")
	seedInternalUser(t, db, 5, common.RoleAdminUser, "default", "admin5-access-token")

	tokens := []*model.Token{
		seedInternalLookupToken(t, db, 4, "ordinary-token", "ordinary-key-secret", "default", false),
		seedInternalLookupToken(t, db, 5, "peer-admin-token", "peer-admin-key-secret", "default", false),
		seedInternalLookupToken(t, db, 2, "root-token", "root-key-secret", "default", false),
	}
	ids := make([]int, 0, len(tokens))
	for _, token := range tokens {
		ids = append(ids, token.Id)
	}

	adminCtx, adminRecorder := newAuthenticatedContext(t, http.MethodPost, "/api/token/admin/batch/keys", TokenBatch{Ids: ids}, 1)
	adminCtx.Set("role", common.RoleAdminUser)
	AdminGetTokenKeysBatch(adminCtx)

	adminResponse := decodeAPIResponse(t, adminRecorder)
	if adminResponse.Success {
		t.Fatalf("expected role-10 administrator batch key reveal to fail")
	}
	for _, token := range tokens {
		if strings.Contains(adminRecorder.Body.String(), token.Key) {
			t.Fatalf("role-10 administrator batch response leaked raw token key %q: %s", token.Key, adminRecorder.Body.String())
		}
	}

	rootCtx, rootRecorder := newAuthenticatedContext(t, http.MethodPost, "/api/token/admin/batch/keys", TokenBatch{Ids: ids}, 2)
	rootCtx.Set("role", common.RoleRootUser)
	AdminGetTokenKeysBatch(rootCtx)

	rootResponse := decodeAPIResponse(t, rootRecorder)
	if !rootResponse.Success {
		t.Fatalf("expected root batch key reveal to succeed, got message: %s", rootResponse.Message)
	}
	var keyData adminTokenKeysResponse
	if err := common.Unmarshal(rootResponse.Data, &keyData); err != nil {
		t.Fatalf("failed to decode root batch token key response: %v", err)
	}
	if len(keyData.Keys) != len(tokens) {
		t.Fatalf("expected %d root-visible keys, got %d", len(tokens), len(keyData.Keys))
	}
	for _, token := range tokens {
		if keyData.Keys[token.Id] != token.GetFullKey() {
			t.Fatalf("expected root to receive full key for token %d", token.Id)
		}
	}
}

func TestAdminGetTokenKeysBatchRouteRejectsAdminButAcceptsRoot(t *testing.T) {
	db := setupInternalTokenControllerTestDB(t)
	seedInternalUser(t, db, 1, common.RoleAdminUser, "default", "admin-access-token")
	seedInternalUser(t, db, 2, common.RoleRootUser, "default", "root-access-token")
	seedInternalUser(t, db, 4, common.RoleCommonUser, "default", "user4-access-token")

	tokens := []*model.Token{
		seedInternalLookupToken(t, db, 4, "ordinary-token", "ordinary-route-key-secret", "default", false),
		seedInternalLookupToken(t, db, 2, "root-token", "root-route-key-secret", "default", false),
	}
	ids := []int{tokens[0].Id, tokens[1].Id}
	body, err := common.Marshal(TokenBatch{Ids: ids})
	if err != nil {
		t.Fatalf("failed to marshal batch request: %v", err)
	}

	router := newAdminTokenSearchRouter()
	adminRequest := httptest.NewRequest(http.MethodPost, "/api/token/admin/batch/keys", bytes.NewReader(body))
	adminRequest.Header.Set("Content-Type", "application/json")
	adminRequest.Header.Set("Authorization", "Bearer admin-access-token")
	adminRequest.Header.Set("New-Api-User", "1")
	adminRecorder := httptest.NewRecorder()
	router.ServeHTTP(adminRecorder, adminRequest)

	adminResponse := decodeAPIResponse(t, adminRecorder)
	if adminResponse.Success {
		t.Fatalf("expected role-10 administrator batch key reveal to fail")
	}
	for _, token := range tokens {
		if strings.Contains(adminRecorder.Body.String(), token.Key) {
			t.Fatalf("role-10 administrator batch response leaked raw token key %q: %s", token.Key, adminRecorder.Body.String())
		}
	}

	rootRequest := httptest.NewRequest(http.MethodPost, "/api/token/admin/batch/keys", bytes.NewReader(body))
	rootRequest.Header.Set("Content-Type", "application/json")
	rootRequest.Header.Set("Authorization", "Bearer root-access-token")
	rootRequest.Header.Set("New-Api-User", "2")
	rootRecorder := httptest.NewRecorder()
	router.ServeHTTP(rootRecorder, rootRequest)

	rootResponse := decodeAPIResponse(t, rootRecorder)
	if !rootResponse.Success {
		t.Fatalf("expected root batch key reveal to succeed, got message: %s", rootResponse.Message)
	}
	var keyData adminTokenKeysResponse
	if err := common.Unmarshal(rootResponse.Data, &keyData); err != nil {
		t.Fatalf("failed to decode root batch token key response: %v", err)
	}
	for _, token := range tokens {
		if keyData.Keys[token.Id] != token.GetFullKey() {
			t.Fatalf("expected root to receive full key for token %d", token.Id)
		}
	}
}
