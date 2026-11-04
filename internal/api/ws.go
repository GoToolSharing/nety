package api

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/coder/websocket"
	"github.com/coder/websocket/wsjson"

	"github.com/GoToolSharing/nety/internal/bus"
	"github.com/GoToolSharing/nety/internal/model"
)

// handleEvents upgrades to a WebSocket and streams the live events of a
// mission: this is what makes results appear in the UI while a scan runs
// (requirement R1), instead of waiting for it to finish.
func (a *API) handleEvents(w http.ResponseWriter, r *http.Request, u model.User) {
	m, ok := a.requireMission(w, r, u)
	if !ok {
		return
	}

	conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{
		// The SPA is served from the same origin as the API; a browser cannot
		// forge the Origin header, so same-origin is the whole check we need.
		OriginPatterns:  []string{},
		CompressionMode: websocket.CompressionContextTakeover,
	})
	if err != nil {
		a.Log.Debug("websocket upgrade failed", "error", err)
		return
	}
	defer conn.CloseNow()

	// The connection outlives the request context in Go's http server only if
	// we detach it: derive our own, cancelled when the client goes away.
	ctx, cancel := context.WithCancel(context.WithoutCancel(r.Context()))
	defer cancel()

	sub := a.Bus.Subscribe(m.ID, 1024)
	defer sub.Close()

	// A reader goroutine: we do not expect client messages, but reading is how
	// close frames and pongs are processed.
	go func() {
		defer cancel()
		for {
			if _, _, err := conn.Read(ctx); err != nil {
				return
			}
		}
	}()

	// Tell the client what it is attached to, and whether a scan is running.
	hello := map[string]any{
		"mission_id":    m.ID,
		"server_time":   time.Now().UTC(),
		"running_scans": a.Runner.Running(),
	}
	if err := writeJSON(ctx, conn, model.Event{
		Type: "hello", MissionID: m.ID, Time: time.Now().UTC(), Data: hello,
	}); err != nil {
		return
	}

	ping := time.NewTicker(30 * time.Second)
	defer ping.Stop()

	var lastDropped int64
	for {
		select {
		case <-ctx.Done():
			return

		case ev, open := <-sub.C():
			if !open {
				_ = conn.Close(websocket.StatusGoingAway, "server shutting down")
				return
			}
			if err := writeJSON(ctx, conn, ev); err != nil {
				return
			}
			// If this client fell behind, the bus dropped events for it. Say so,
			// so the UI refetches instead of showing a half-updated table.
			if dropped := sub.Dropped(); dropped > lastDropped {
				lastDropped = dropped
				_ = writeJSON(ctx, conn, model.Event{
					Type:      model.EvtScanLog,
					MissionID: m.ID,
					Time:      time.Now().UTC(),
					Data: model.LogLine{
						Level:   "warn",
						Message: "events dropped, resynchronise",
					},
				})
			}

		case <-ping.C:
			pctx, pcancel := context.WithTimeout(ctx, 10*time.Second)
			err := conn.Ping(pctx)
			pcancel()
			if err != nil {
				return
			}
		}
	}
}

// writeJSON sends one event with a write deadline, so a stalled client cannot
// block the publisher forever.
func writeJSON(ctx context.Context, conn *websocket.Conn, ev model.Event) error {
	wctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	return wsjson.Write(wctx, conn, ev)
}

var (
	_ = json.Marshal
	_ = bus.DefaultBuffer
)
