package controller

import (
	"errors"
	"strconv"
	"strings"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/i18n"
	"github.com/QuantumNous/new-api/model"
	"github.com/gin-gonic/gin"
)

type internalAdminUpdateUserRequest struct {
	Username    *string `json:"username"`
	Password    *string `json:"password"`
	DisplayName *string `json:"display_name"`
	Group       *string `json:"group"`
	Quota       *int    `json:"quota"`
	Remark      *string `json:"remark"`
	Note        *string `json:"note"`
}

func InternalAdminListUsers(c *gin.Context) {
	pageInfo, err := adminListUsers(common.GetPageQuery(c))
	if err != nil {
		common.ApiError(c, err)
		return
	}
	common.ApiSuccess(c, pageInfo)
}

func InternalAdminSearchUsers(c *gin.Context) {
	pageInfo, err := adminSearchUsers(c.Query("keyword"), c.Query("group"), common.GetPageQuery(c))
	if err != nil {
		common.ApiError(c, err)
		return
	}
	common.ApiSuccess(c, pageInfo)
}

func InternalAdminGetUser(c *gin.Context) {
	userID, err := parseIntParam(c, "id")
	if err != nil {
		common.ApiError(c, err)
		return
	}
	user, err := adminGetUserByID(c.GetInt("role"), userID)
	if err != nil {
		if errors.Is(err, errAdminPermissionSameLevel) {
			common.ApiErrorI18n(c, i18n.MsgUserNoPermissionSameLevel)
			return
		}
		common.ApiError(c, err)
		return
	}
	common.ApiSuccess(c, user)
}

func InternalAdminCreateUser(c *gin.Context) {
	var req model.User
	if err := common.DecodeJson(c.Request.Body, &req); err != nil {
		common.ApiErrorI18n(c, i18n.MsgInvalidParams)
		return
	}
	req.Username = strings.TrimSpace(req.Username)
	if req.Username == "" || req.Password == "" {
		common.ApiErrorI18n(c, i18n.MsgInvalidParams)
		return
	}
	if req.DisplayName == "" {
		req.DisplayName = req.Username
	}
	createdUser, err := adminCreateUser(c.GetInt("role"), adminCreateUserInput{
		Username:    req.Username,
		Password:    req.Password,
		DisplayName: req.DisplayName,
		Role:        req.Role,
	})
	if err != nil {
		if errors.Is(err, errAdminCreateHigherLevel) {
			common.ApiErrorI18n(c, i18n.MsgUserCannotCreateHigherLevel)
			return
		}
		if errors.Is(err, errAdminInputInvalid) {
			common.ApiErrorI18n(c, i18n.MsgUserInputInvalid, map[string]any{"Error": err.Error()})
			return
		}
		if errors.Is(err, errAdminInvalidParams) {
			common.ApiErrorI18n(c, i18n.MsgInvalidParams)
			return
		}
		common.ApiError(c, err)
		return
	}
	common.ApiSuccess(c, createdUser)
}

func InternalAdminUpdateUser(c *gin.Context) {
	userID, err := parseIntParam(c, "id")
	if err != nil {
		common.ApiError(c, err)
		return
	}
	var req internalAdminUpdateUserRequest
	if err = common.DecodeJson(c.Request.Body, &req); err != nil {
		common.ApiErrorI18n(c, i18n.MsgInvalidParams)
		return
	}
	updatedUser, err := adminUpdateUser(c.GetInt("role"), adminUpdateUserInput{
		ID:          userID,
		Username:    req.Username,
		Password:    req.Password,
		DisplayName: req.DisplayName,
		Group:       req.Group,
		Quota:       req.Quota,
		Remark:      req.Remark,
		Note:        req.Note,
	})
	if err != nil {
		if errors.Is(err, errAdminPermissionHigherLevel) {
			common.ApiErrorI18n(c, i18n.MsgUserNoPermissionHigherLevel)
			return
		}
		if errors.Is(err, errAdminInputInvalid) {
			common.ApiErrorI18n(c, i18n.MsgUserInputInvalid, map[string]any{"Error": err.Error()})
			return
		}
		if errors.Is(err, errAdminInvalidParams) {
			common.ApiErrorI18n(c, i18n.MsgInvalidParams)
			return
		}
		common.ApiError(c, err)
		return
	}
	common.ApiSuccess(c, updatedUser)
}

func InternalAdminDeleteUser(c *gin.Context) {
	userID, err := parseIntParam(c, "id")
	if err != nil {
		common.ApiError(c, err)
		return
	}
	if err = adminDeleteUser(c.GetInt("role"), userID); err != nil {
		if errors.Is(err, errAdminPermissionHigherLevel) {
			common.ApiErrorI18n(c, i18n.MsgUserNoPermissionHigherLevel)
			return
		}
		common.ApiError(c, err)
		return
	}
	common.ApiSuccess(c, gin.H{"id": userID})
}

func parseIntParam(c *gin.Context, key string) (int, error) {
	return strconv.Atoi(c.Param(key))
}
