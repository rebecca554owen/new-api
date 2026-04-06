package controller

import (
	"errors"
	"fmt"
	"strings"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/logger"
	"github.com/QuantumNous/new-api/model"
)

var (
	errAdminPermissionSameLevel   = errors.New("admin permission same level denied")
	errAdminPermissionHigherLevel = errors.New("admin permission higher level denied")
	errAdminInvalidParams         = errors.New("admin invalid params")
	errAdminInputInvalid          = errors.New("admin input invalid")
	errAdminCreateHigherLevel     = errors.New("admin cannot create higher level")
)

type adminCreateUserInput struct {
	Username    string
	Password    string
	DisplayName string
	Role        int
}

type adminUpdateUserInput struct {
	ID          int
	Username    *string
	Password    *string
	DisplayName *string
	Group       *string
	Quota       *int
	Remark      *string
	Note        *string
}

func formatQuotaChangeLog(beforeQuota int, afterQuota int, note *string) string {
	message := fmt.Sprintf("管理员将用户额度从 %s修改为 %s", logger.LogQuota(beforeQuota), logger.LogQuota(afterQuota))
	if note == nil {
		return message
	}
	trimmed := strings.TrimSpace(*note)
	if trimmed == "" {
		return message
	}
	return fmt.Sprintf("%s，备注：%s", message, trimmed)
}

func adminListUsers(pageInfo *common.PageInfo) (*common.PageInfo, error) {
	users, total, err := model.GetAllUsers(pageInfo)
	if err != nil {
		return nil, err
	}
	pageInfo.SetTotal(int(total))
	pageInfo.SetItems(users)
	return pageInfo, nil
}

func adminSearchUsers(keyword string, group string, pageInfo *common.PageInfo) (*common.PageInfo, error) {
	users, total, err := model.SearchUsers(keyword, group, pageInfo.GetStartIdx(), pageInfo.GetPageSize())
	if err != nil {
		return nil, err
	}
	pageInfo.SetTotal(int(total))
	pageInfo.SetItems(users)
	return pageInfo, nil
}

func adminGetUserByID(operatorRole int, userID int) (*model.User, error) {
	user, err := model.GetUserById(userID, false)
	if err != nil {
		return nil, err
	}
	if operatorRole <= user.Role && operatorRole != common.RoleRootUser {
		return nil, errAdminPermissionSameLevel
	}
	return user, nil
}

func adminCreateUser(operatorRole int, input adminCreateUserInput) (*model.User, error) {
	user := model.User{
		Username:    strings.TrimSpace(input.Username),
		Password:    input.Password,
		DisplayName: strings.TrimSpace(input.DisplayName),
		Role:        input.Role,
	}
	if user.Username == "" || user.Password == "" {
		return nil, errAdminInvalidParams
	}
	if user.DisplayName == "" {
		user.DisplayName = user.Username
	}
	if user.Role >= operatorRole {
		return nil, errAdminCreateHigherLevel
	}
	if err := common.Validate.Struct(&user); err != nil {
		return nil, fmt.Errorf("%w: %w", errAdminInputInvalid, err)
	}
	cleanUser := model.User{
		Username:    user.Username,
		Password:    user.Password,
		DisplayName: user.DisplayName,
		Role:        user.Role,
	}
	if err := cleanUser.Insert(0); err != nil {
		return nil, err
	}
	return model.GetUserById(cleanUser.Id, false)
}

func adminUpdateUser(operatorRole int, input adminUpdateUserInput) (*model.User, error) {
	if input.ID == 0 {
		return nil, errAdminInvalidParams
	}
	originUser, err := model.GetUserById(input.ID, false)
	if err != nil {
		return nil, err
	}
	if operatorRole <= originUser.Role && operatorRole != common.RoleRootUser {
		return nil, errAdminPermissionHigherLevel
	}

	updatedUser, err := model.GetUserById(input.ID, true)
	if err != nil {
		return nil, err
	}

	if input.Username != nil {
		updatedUser.Username = strings.TrimSpace(*input.Username)
	}
	if input.Password != nil {
		updatedUser.Password = *input.Password
	} else {
		updatedUser.Password = "$I_LOVE_U"
	}
	if input.DisplayName != nil {
		updatedUser.DisplayName = strings.TrimSpace(*input.DisplayName)
	}
	if input.Group != nil {
		updatedUser.Group = strings.TrimSpace(*input.Group)
	}
	if input.Quota != nil {
		updatedUser.Quota = *input.Quota
	}
	if input.Remark != nil {
		updatedUser.Remark = *input.Remark
	}

	if err := common.Validate.Struct(updatedUser); err != nil {
		return nil, fmt.Errorf("%w: %w", errAdminInputInvalid, err)
	}
	if updatedUser.Password == "$I_LOVE_U" {
		updatedUser.Password = ""
	}

	updatePassword := updatedUser.Password != ""
	if err := updatedUser.Edit(updatePassword); err != nil {
		return nil, err
	}
	if originUser.Quota != updatedUser.Quota {
		model.RecordLog(originUser.Id, model.LogTypeManage, formatQuotaChangeLog(originUser.Quota, updatedUser.Quota, input.Note))
	}
	return model.GetUserById(updatedUser.Id, false)
}

func adminDeleteUser(operatorRole int, userID int) error {
	originUser, err := model.GetUserById(userID, false)
	if err != nil {
		return err
	}
	if operatorRole <= originUser.Role {
		return errAdminPermissionHigherLevel
	}
	return model.HardDeleteUserById(userID)
}
