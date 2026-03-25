package controller

import (
	"strconv"
	"strings"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/model"
	"github.com/gin-gonic/gin"
)

func AdminSearchTokens(c *gin.Context) {
	pageInfo := common.GetPageQuery(c)
	tokenQuery := strings.TrimSpace(c.Query("token"))
	keywordQuery := strings.TrimSpace(c.Query("q"))

	var tokens []*model.Token
	if token := adminFindToken(tokenQuery, keywordQuery); token != nil {
		if err := adminPopulateTokenGroup(token); err != nil {
			common.ApiError(c, err)
			return
		}
		startIdx := pageInfo.GetStartIdx()
		if startIdx == 0 {
			tokens = []*model.Token{token}
		} else {
			tokens = []*model.Token{}
		}
		pageInfo.SetTotal(1)
	} else {
		tokens = []*model.Token{}
		pageInfo.SetTotal(0)
	}

	pageInfo.SetItems(buildMaskedTokenResponses(tokens))
	common.ApiSuccess(c, pageInfo)
}

func AdminGetToken(c *gin.Context) {
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		common.ApiError(c, err)
		return
	}

	token, err := model.GetTokenById(id)
	if err != nil {
		common.ApiError(c, err)
		return
	}
	if err := adminPopulateTokenGroup(token); err != nil {
		common.ApiError(c, err)
		return
	}

	common.ApiSuccess(c, buildMaskedTokenResponse(token))
}

func AdminGrantTokenQuota(c *gin.Context) {
	GrantTokenQuota(c)
}

func adminFindToken(tokenQuery string, keywordQuery string) *model.Token {
	for _, candidate := range []string{tokenQuery, keywordQuery} {
		normalized := strings.TrimSpace(candidate)
		if normalized == "" {
			continue
		}
		normalized = strings.TrimPrefix(normalized, "sk-")
		token, err := model.GetTokenByKey(normalized, false)
		if err == nil && token != nil {
			return token
		}
	}
	return nil
}

func adminPopulateTokenGroup(token *model.Token) error {
	if token == nil || token.Group != "" {
		return nil
	}
	userCache, err := model.GetUserCache(token.UserId)
	if err != nil {
		return err
	}
	token.Group = userCache.Group
	return nil
}
