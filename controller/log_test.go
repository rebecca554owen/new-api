package controller

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/model"
	"github.com/gin-gonic/gin"
)

func seedTokenLogsForGetLogByKey(t *testing.T, tokenId int) {
	t.Helper()

	logs := []model.Log{
		{UserId: 1, TokenId: tokenId, CreatedAt: 10, Type: model.LogTypeConsume, Content: "older"},
		{UserId: 1, TokenId: tokenId, CreatedAt: 20, Type: model.LogTypeConsume, Content: "middle"},
		{UserId: 1, TokenId: tokenId + 1, CreatedAt: 30, Type: model.LogTypeConsume, Content: "other-token"},
		{UserId: 1, TokenId: tokenId, CreatedAt: 30, Type: model.LogTypeConsume, Content: "newer"},
		{UserId: 1, TokenId: tokenId, CreatedAt: 40, Type: model.LogTypeConsume, Content: "newest"},
	}
	if err := model.LOG_DB.Create(&logs).Error; err != nil {
		t.Fatalf("failed to seed token logs: %v", err)
	}
}

func performGetLogByKey(t *testing.T, target string, tokenId int) *httptest.ResponseRecorder {
	t.Helper()

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, target, nil)
	c.Set("token_id", tokenId)
	GetLogByKey(c)
	return w
}

func TestGetLogByKeyKeepsLegacyArrayResponse(t *testing.T) {
	setupTokenControllerTestDB(t)
	seedTokenLogsForGetLogByKey(t, 7)

	w := performGetLogByKey(t, "/api/log/token", 7)
	if w.Code != http.StatusOK {
		t.Fatalf("expected http 200, got %d", w.Code)
	}

	var response struct {
		Success bool        `json:"success"`
		Data    []model.Log `json:"data"`
	}
	if err := common.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if !response.Success {
		t.Fatalf("expected success response")
	}
	if len(response.Data) != 4 {
		t.Fatalf("expected 4 logs, got %d", len(response.Data))
	}
	if response.Data[0].Content != "newest" || response.Data[0].Id != 1 {
		t.Fatalf("unexpected first legacy log: %+v", response.Data[0])
	}
}

func TestGetLogByKeySupportsPagedRangeResponse(t *testing.T) {
	setupTokenControllerTestDB(t)
	seedTokenLogsForGetLogByKey(t, 7)

	w := performGetLogByKey(t, "/api/log/token?p=2&page_size=2&start_timestamp=20&end_timestamp=40", 7)
	if w.Code != http.StatusOK {
		t.Fatalf("expected http 200, got %d", w.Code)
	}

	var response struct {
		Success bool `json:"success"`
		Data    struct {
			Page     int         `json:"page"`
			PageSize int         `json:"page_size"`
			Total    int         `json:"total"`
			Items    []model.Log `json:"items"`
		} `json:"data"`
	}
	if err := common.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if !response.Success {
		t.Fatalf("expected success response")
	}
	if response.Data.Page != 2 || response.Data.PageSize != 2 || response.Data.Total != 3 {
		t.Fatalf("unexpected page metadata: %+v", response.Data)
	}
	if len(response.Data.Items) != 1 {
		t.Fatalf("expected 1 log on second page, got %d", len(response.Data.Items))
	}
	if response.Data.Items[0].Content != "middle" || response.Data.Items[0].Id != 3 {
		t.Fatalf("unexpected paged log: %+v", response.Data.Items[0])
	}
}
