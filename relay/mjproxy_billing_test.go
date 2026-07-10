package relay

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/dto"
	"github.com/QuantumNous/new-api/model"
	relaycommon "github.com/QuantumNous/new-api/relay/common"
	relayconstant "github.com/QuantumNous/new-api/relay/constant"
	"github.com/QuantumNous/new-api/service"
	"github.com/QuantumNous/new-api/setting/ratio_setting"
	"github.com/gin-gonic/gin"
	"github.com/glebarez/sqlite"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

func TestMain(m *testing.M) {
	common.RedisEnabled = false
	common.BatchUpdateEnabled = false
	common.LogConsumeEnabled = false
	common.UsingSQLite = true
	common.UsingMySQL = false
	common.UsingPostgreSQL = false
	ratio_setting.InitRatioSettings()
	service.InitHttpClient()
	os.Exit(m.Run())
}

func setupMidjourneyBillingTest(t *testing.T, userQuota int, tokenQuota int) (*model.User, *model.Token) {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(filepath.Join(t.TempDir(), "midjourney-billing.db")), &gorm.Config{})
	require.NoError(t, err)
	sqlDB, err := db.DB()
	require.NoError(t, err)
	sqlDB.SetMaxOpenConns(1)
	require.NoError(t, db.AutoMigrate(&model.User{}, &model.Token{}, &model.Midjourney{}, &model.Channel{}, &model.Log{}))

	oldDB := model.DB
	oldLogDB := model.LOG_DB
	model.DB = db
	model.LOG_DB = db
	t.Cleanup(func() {
		model.DB = oldDB
		model.LOG_DB = oldLogDB
		if sqlDB, dbErr := db.DB(); dbErr == nil {
			_ = sqlDB.Close()
		}
	})

	user := &model.User{Username: fmt.Sprintf("mj-wallet-%d", time.Now().UnixNano()), Status: common.UserStatusEnabled, Quota: userQuota}
	require.NoError(t, db.Create(user).Error)
	token := &model.Token{
		UserId:      user.Id,
		Name:        "mj-wallet-token",
		Key:         fmt.Sprintf("mj-wallet-key-%d", time.Now().UnixNano()),
		Status:      common.TokenStatusEnabled,
		RemainQuota: tokenQuota,
		ExpiredTime: -1,
	}
	require.NoError(t, db.Create(token).Error)
	return user, token
}

func newMidjourneyBillingContext(path string, body string, baseURL string, user *model.User, token *model.Token, modelName string, relayMode int) (*gin.Context, *relaycommon.RelayInfo) {
	recorder := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(recorder)
	c.Request = httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	c.Request.Header.Set("Content-Type", "application/json")
	c.Set("base_url", baseURL)
	c.Set("channel_id", 0)

	return c, &relaycommon.RelayInfo{
		UserId:          user.Id,
		TokenId:         token.Id,
		TokenKey:        token.Key,
		OriginModelName: modelName,
		UsingGroup:      "default",
		UserGroup:       "default",
		RelayMode:       relayMode,
		StartTime:       time.Now(),
	}
}

func persistedMidjourneyQuota(t *testing.T, userID int, tokenID int) (int, int) {
	t.Helper()
	var user model.User
	var token model.Token
	require.NoError(t, model.DB.First(&user, userID).Error)
	require.NoError(t, model.DB.First(&token, tokenID).Error)
	return user.Quota, token.RemainQuota
}

func TestRelaySwapFaceOnlyAffordableRequestReachesUpstream(t *testing.T) {
	price, ok := ratio_setting.GetDefaultModelPriceMap()["swap_face"]
	require.True(t, ok)
	quota := common.QuotaFromFloat(price * common.QuotaPerUnit)
	user, token := setupMidjourneyBillingTest(t, quota, quota*2)

	entered := make(chan struct{})
	release := make(chan struct{})
	var upstreamCalls atomic.Int32
	var observedWallet atomic.Int64
	var observedToken atomic.Int64
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		upstreamCalls.Add(1)
		var storedUser model.User
		var storedToken model.Token
		if err := model.DB.First(&storedUser, user.Id).Error; err == nil {
			observedWallet.Store(int64(storedUser.Quota))
		}
		if err := model.DB.First(&storedToken, token.Id).Error; err == nil {
			observedToken.Store(int64(storedToken.RemainQuota))
		}
		close(entered)
		<-release
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"code":1,"description":"ok","result":"mj-one"}`))
	}))
	defer upstream.Close()

	firstCtx, firstInfo := newMidjourneyBillingContext("/swap", `{"sourceBase64":"a","targetBase64":"b"}`, upstream.URL, user, token, "swap_face", relayconstant.RelayModeSwapFace)
	firstDone := make(chan *dto.MidjourneyResponse, 1)
	go func() { firstDone <- RelaySwapFace(firstCtx, firstInfo) }()
	<-entered
	assert.Zero(t, observedWallet.Load())
	assert.Equal(t, int64(quota), observedToken.Load())

	secondCtx, secondInfo := newMidjourneyBillingContext("/swap", `{"sourceBase64":"a","targetBase64":"b"}`, upstream.URL, user, token, "swap_face", relayconstant.RelayModeSwapFace)
	secondErr := RelaySwapFace(secondCtx, secondInfo)
	require.NotNil(t, secondErr)
	assert.Equal(t, "quota_not_enough", secondErr.Description)
	assert.Equal(t, int32(1), upstreamCalls.Load())

	close(release)
	require.Nil(t, <-firstDone)
	userQuota, tokenQuota := persistedMidjourneyQuota(t, user.Id, token.Id)
	assert.Zero(t, userQuota)
	assert.Equal(t, quota, tokenQuota)
}

func TestRelayMidjourneySubmitInsufficientQuotaDoesNotDispatch(t *testing.T) {
	price, ok := ratio_setting.GetDefaultModelPriceMap()["mj_imagine"]
	require.True(t, ok)
	quota := common.QuotaFromFloat(price * common.QuotaPerUnit)
	user, token := setupMidjourneyBillingTest(t, 0, quota)
	var upstreamCalls atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		upstreamCalls.Add(1)
		_, _ = w.Write([]byte(`{"code":1,"description":"unexpected","result":"mj"}`))
	}))
	defer upstream.Close()

	c, info := newMidjourneyBillingContext("/submit", `{"prompt":"test"}`, upstream.URL, user, token, "mj_imagine", relayconstant.RelayModeMidjourneyImagine)
	mjErr := RelayMidjourneySubmit(c, info)
	require.NotNil(t, mjErr)
	assert.Equal(t, "quota_not_enough", mjErr.Description)
	assert.Zero(t, upstreamCalls.Load())
}

func TestRelaySwapFaceRejectedResponseRefundsReservation(t *testing.T) {
	price, ok := ratio_setting.GetDefaultModelPriceMap()["swap_face"]
	require.True(t, ok)
	quota := common.QuotaFromFloat(price * common.QuotaPerUnit)
	user, token := setupMidjourneyBillingTest(t, quota, quota)

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"code":24,"description":"rejected","result":""}`))
	}))
	defer upstream.Close()

	c, info := newMidjourneyBillingContext("/swap", `{"sourceBase64":"a","targetBase64":"b"}`, upstream.URL, user, token, "swap_face", relayconstant.RelayModeSwapFace)
	require.Nil(t, RelaySwapFace(c, info))
	require.Eventually(t, func() bool {
		userQuota, tokenQuota := persistedMidjourneyQuota(t, user.Id, token.Id)
		return userQuota == quota && tokenQuota == quota
	}, 2*time.Second, 10*time.Millisecond)

	var task model.Midjourney
	require.NoError(t, model.DB.First(&task).Error)
	assert.Zero(t, task.Quota)
}

func TestRelayMidjourneyInpaintDispatchesWithoutReservation(t *testing.T) {
	user, token := setupMidjourneyBillingTest(t, 0, 0)
	var upstreamCalls atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		upstreamCalls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"code":1,"description":"ok","result":"mj-inpaint"}`))
	}))
	defer upstream.Close()

	baseURL := upstream.URL
	channel := &model.Channel{Name: "mj-inpaint-channel", Key: "mj-secret", Status: common.ChannelStatusEnabled, BaseURL: &baseURL}
	require.NoError(t, model.DB.Create(channel).Error)
	require.NoError(t, model.DB.Create(&model.Midjourney{
		UserId:    user.Id,
		MjId:      "mj-origin",
		Prompt:    "origin",
		Status:    "SUCCESS",
		Progress:  "100%",
		ChannelId: channel.Id,
	}).Error)

	c, info := newMidjourneyBillingContext("/submit", `{"taskId":"mj-origin","action":"INPAINT","index":1}`, upstream.URL, user, token, "mj_inpaint", relayconstant.RelayModeMidjourneyChange)
	require.Nil(t, RelayMidjourneySubmit(c, info))
	assert.Equal(t, int32(1), upstreamCalls.Load())
	assert.Nil(t, info.Billing)

	userQuota, tokenQuota := persistedMidjourneyQuota(t, user.Id, token.Id)
	assert.Zero(t, userQuota)
	assert.Zero(t, tokenQuota)
	var submitted model.Midjourney
	require.NoError(t, model.DB.Where("mj_id = ?", "mj-inpaint").First(&submitted).Error)
	assert.Zero(t, submitted.Quota)
}
