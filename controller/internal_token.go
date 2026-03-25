package controller

import (
	"errors"
	"strings"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/model"
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

type ResolveTokenByKeyRequest struct {
	Key string `json:"key"`
}

type ResolveTokenByKeyResponse struct {
	TokenID        int    `json:"tokenId"`
	UserID         int    `json:"userId"`
	Name           string `json:"name"`
	Group          string `json:"group"`
	Status         int    `json:"status"`
	ExpiredTime    int64  `json:"expiredTime"`
	UnlimitedQuota bool   `json:"unlimitedQuota"`
}

func ResolveTokenByKey(c *gin.Context) {
	var req ResolveTokenByKeyRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		common.ApiErrorMsg(c, "invalid request body")
		return
	}

	key := strings.TrimSpace(req.Key)
	if key == "" || !strings.HasPrefix(key, "sk-") {
		common.ApiErrorMsg(c, "invalid key format")
		return
	}

	trimmedKey := strings.TrimPrefix(key, "sk-")
	if trimmedKey == "" {
		common.ApiErrorMsg(c, "invalid key format")
		return
	}

	token, err := model.GetTokenByKey(trimmedKey, false)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			common.ApiErrorMsg(c, "token not found")
			return
		}
		common.ApiError(c, err)
		return
	}

	group, err := resolveTokenGroup(token)
	if err != nil {
		common.ApiError(c, err)
		return
	}

	common.ApiSuccess(c, ResolveTokenByKeyResponse{
		TokenID:        token.Id,
		UserID:         token.UserId,
		Name:           token.Name,
		Group:          group,
		Status:         token.Status,
		ExpiredTime:    token.ExpiredTime,
		UnlimitedQuota: token.UnlimitedQuota,
	})
}

func resolveTokenGroup(token *model.Token) (string, error) {
	if token == nil {
		return "", errors.New("token not found")
	}
	if token.Group != "" {
		return token.Group, nil
	}

	userCache, err := model.GetUserCache(token.UserId)
	if err != nil {
		return "", err
	}
	return userCache.Group, nil
}
