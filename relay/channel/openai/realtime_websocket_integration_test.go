package openai

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/dto"
	"github.com/QuantumNous/new-api/model"
	relaycommon "github.com/QuantumNous/new-api/relay/common"
	"github.com/QuantumNous/new-api/service"
	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type realtimeHandlerResult struct {
	err   error
	usage *dto.RealtimeUsage
}

func newRealtimeWebsocketPair(t *testing.T) (*websocket.Conn, *websocket.Conn) {
	t.Helper()

	serverConnCh := make(chan *websocket.Conn, 1)
	upgradeErrCh := make(chan error, 1)
	upgrader := websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			upgradeErrCh <- err
			return
		}
		serverConnCh <- conn
	}))

	peerConn, _, err := websocket.DefaultDialer.Dial(
		"ws"+strings.TrimPrefix(server.URL, "http"),
		nil,
	)
	require.NoError(t, err)

	var handlerConn *websocket.Conn
	select {
	case handlerConn = <-serverConnCh:
	case err = <-upgradeErrCh:
		require.NoError(t, err)
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for websocket upgrade")
	}

	t.Cleanup(func() {
		_ = peerConn.Close()
		_ = handlerConn.Close()
		server.Close()
	})
	return handlerConn, peerConn
}

func newRealtimeHandlerContext(t *testing.T) (*gin.Context, context.CancelFunc) {
	t.Helper()

	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	requestContext, cancel := context.WithCancel(context.Background())
	c.Request = httptest.NewRequest(http.MethodGet, "http://example.test/v1/realtime", nil).
		WithContext(requestContext)
	t.Cleanup(cancel)
	return c, cancel
}

func marshalRealtimeEvent(t *testing.T, event dto.RealtimeEvent) []byte {
	t.Helper()

	payload, err := common.Marshal(event)
	require.NoError(t, err)
	return payload
}

func startRealtimeHandler(
	t *testing.T,
	info *relaycommon.RelayInfo,
) (<-chan realtimeHandlerResult, context.CancelFunc) {
	t.Helper()

	c, cancel := newRealtimeHandlerContext(t)
	resultCh := make(chan realtimeHandlerResult, 1)
	go func() {
		handlerErr, usage := OpenaiRealtimeHandler(c, info)
		var err error
		if handlerErr != nil {
			err = handlerErr
		}
		resultCh <- realtimeHandlerResult{err: err, usage: usage}
	}()
	return resultCh, cancel
}

func awaitRealtimeHandlerResult(t *testing.T, resultCh <-chan realtimeHandlerResult) realtimeHandlerResult {
	t.Helper()

	select {
	case result := <-resultCh:
		return result
	case <-time.After(3 * time.Second):
		t.Fatal("realtime handler did not return after websocket shutdown")
		return realtimeHandlerResult{}
	}
}

func TestOpenaiRealtimeHandlerConcurrentTrafficClientDisconnectsFirst(t *testing.T) {
	clientHandlerConn, clientPeerConn := newRealtimeWebsocketPair(t)
	targetHandlerConn, targetPeerConn := newRealtimeWebsocketPair(t)

	billing := &recordingRealtimeBilling{initial: 10, current: 10}
	info := realtimeBillingTestInfo(billing)
	info.ChannelMeta = &relaycommon.ChannelMeta{UpstreamModelName: "gpt-4o-realtime-preview"}
	info.ClientWs = clientHandlerConn
	info.TargetWs = targetHandlerConn
	info.OriginModelName = "gpt-4o-realtime-preview"

	resultCh, cancel := startRealtimeHandler(t, info)
	defer cancel()

	const messageCount = 24
	clientPayload := marshalRealtimeEvent(t, dto.RealtimeEvent{
		EventId: "client-request",
		Type:    dto.RealtimeEventTypeResponseCreate,
	})
	targetPayload := marshalRealtimeEvent(t, dto.RealtimeEvent{
		EventId: "upstream-response",
		Type:    dto.RealtimeEventTypeResponseDone,
		Response: &dto.RealtimeResponse{Usage: &dto.RealtimeUsage{
			TotalTokens:  3,
			InputTokens:  2,
			OutputTokens: 1,
			InputTokenDetails: dto.InputTokenDetails{
				TextTokens: 2,
			},
			OutputTokenDetails: dto.OutputTokenDetails{
				TextTokens: 1,
			},
		}},
	})

	deadline := time.Now().Add(3 * time.Second)
	require.NoError(t, clientPeerConn.SetReadDeadline(deadline))
	require.NoError(t, clientPeerConn.SetWriteDeadline(deadline))
	require.NoError(t, targetPeerConn.SetReadDeadline(deadline))
	require.NoError(t, targetPeerConn.SetWriteDeadline(deadline))

	start := make(chan struct{})
	errCh := make(chan error, 4)
	var trafficWG sync.WaitGroup
	trafficWG.Add(4)

	go func() {
		defer trafficWG.Done()
		<-start
		for i := 0; i < messageCount; i++ {
			if err := clientPeerConn.WriteMessage(websocket.TextMessage, clientPayload); err != nil {
				errCh <- fmt.Errorf("client write %d: %w", i, err)
				return
			}
		}
	}()
	go func() {
		defer trafficWG.Done()
		<-start
		for i := 0; i < messageCount; i++ {
			if err := targetPeerConn.WriteMessage(websocket.TextMessage, targetPayload); err != nil {
				errCh <- fmt.Errorf("target write %d: %w", i, err)
				return
			}
		}
	}()
	go func() {
		defer trafficWG.Done()
		<-start
		for i := 0; i < messageCount; i++ {
			if _, _, err := targetPeerConn.ReadMessage(); err != nil {
				errCh <- fmt.Errorf("target read %d: %w", i, err)
				return
			}
		}
	}()
	go func() {
		defer trafficWG.Done()
		<-start
		for i := 0; i < messageCount; i++ {
			if _, _, err := clientPeerConn.ReadMessage(); err != nil {
				errCh <- fmt.Errorf("client read %d: %w", i, err)
				return
			}
		}
	}()

	close(start)
	trafficWG.Wait()
	close(errCh)
	for err := range errCh {
		require.NoError(t, err)
	}

	// The downstream client initiates shutdown while the upstream reader is
	// still live. The handler must close the other side, join both readers, and
	// only then snapshot the cumulative usage.
	require.NoError(t, clientPeerConn.WriteControl(
		websocket.CloseMessage,
		websocket.FormatCloseMessage(websocket.CloseNormalClosure, "client done"),
		time.Now().Add(time.Second),
	))

	result := awaitRealtimeHandlerResult(t, resultCh)
	require.NoError(t, result.err)
	require.NotNil(t, result.usage)
	assert.Equal(t, messageCount*3, result.usage.TotalTokens)
	assert.Equal(t, messageCount*2, result.usage.InputTokens)
	assert.Equal(t, messageCount, result.usage.OutputTokens)
	assert.Equal(t, messageCount*2, result.usage.InputTokenDetails.TextTokens)
	assert.Equal(t, messageCount, result.usage.OutputTokenDetails.TextTokens)
	assert.Len(t, billing.targets, messageCount)
	assert.Equal(t, 10+messageCount*3, billing.current)
}

func TestOpenaiRealtimeHandlerReserveFailureDoesNotCountLocalTailTwice(t *testing.T) {
	clientHandlerConn, clientPeerConn := newRealtimeWebsocketPair(t)
	targetHandlerConn, targetPeerConn := newRealtimeWebsocketPair(t)

	billing := &recordingRealtimeBilling{
		initial: 10,
		current: 10,
		err:     model.ErrInsufficientUserQuota,
	}
	info := realtimeBillingTestInfo(billing)
	info.ChannelMeta = &relaycommon.ChannelMeta{UpstreamModelName: "gpt-4o-realtime-preview"}
	info.ClientWs = clientHandlerConn
	info.TargetWs = targetHandlerConn
	info.OriginModelName = "gpt-4o-realtime-preview"

	resultCh, cancel := startRealtimeHandler(t, info)
	defer cancel()

	localEvent := dto.RealtimeEvent{
		EventId: "local-estimate",
		Type:    dto.RealtimeEventResponseAudioTranscriptionDelta,
		Delta:   "this local estimate must be cleared after official usage arrives",
	}
	localTextTokens, _, err := service.CountTokenRealtime(info, localEvent, info.UpstreamModelName)
	require.NoError(t, err)
	require.Positive(t, localTextTokens)

	deadline := time.Now().Add(3 * time.Second)
	require.NoError(t, targetPeerConn.SetWriteDeadline(deadline))
	require.NoError(t, clientPeerConn.SetReadDeadline(deadline))
	require.NoError(t, targetPeerConn.WriteMessage(
		websocket.TextMessage,
		marshalRealtimeEvent(t, localEvent),
	))
	// Reading the forwarded delta proves the target reader populated localUsage
	// before the following response.done is handled.
	_, forwarded, err := clientPeerConn.ReadMessage()
	require.NoError(t, err)
	assert.Equal(t, marshalRealtimeEvent(t, localEvent), forwarded)

	officialUsage := &dto.RealtimeUsage{
		TotalTokens:  7,
		InputTokens:  4,
		OutputTokens: 3,
		InputTokenDetails: dto.InputTokenDetails{
			TextTokens: 4,
		},
		OutputTokenDetails: dto.OutputTokenDetails{
			TextTokens: 3,
		},
	}
	require.NoError(t, targetPeerConn.WriteMessage(
		websocket.TextMessage,
		marshalRealtimeEvent(t, dto.RealtimeEvent{
			EventId:  "official-usage",
			Type:     dto.RealtimeEventTypeResponseDone,
			Response: &dto.RealtimeResponse{Usage: officialUsage},
		}),
	))

	result := awaitRealtimeHandlerResult(t, resultCh)
	require.NoError(t, result.err)
	require.NotNil(t, result.usage)
	assert.Equal(t, *officialUsage, *result.usage)
	assert.NotEqual(t, officialUsage.TotalTokens+localTextTokens, result.usage.TotalTokens)
	assert.Len(t, billing.targets, 1)
	assert.Equal(t, 10, billing.current)
}
