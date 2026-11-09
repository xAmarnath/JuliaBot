package modules

import (
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"strings"
	"sync"
	"time"

	tg "github.com/xAmarnath/gogram/telegram"
)

//go:embed transfer_progress.html
var transferWidgetHTML string

// ChatData belongs to one transfer message, including in groups. PublicData
// and SharedWidget would share state across messages/forwards unnecessarily.
type transferWidgetState struct {
	Phase   string `json:"phase"`
	Name    string `json:"name"`
	Percent int    `json:"percent"`
	Size    string `json:"size"`
	Speed   string `json:"speed,omitempty"`
	ETA     string `json:"eta,omitempty"`
	Elapsed string `json:"elapsed,omitempty"`
	DC      string `json:"dc,omitempty"`
	Part    int64  `json:"part,omitempty"`
	Parts   int64  `json:"parts,omitempty"`
	Detail  string `json:"detail,omitempty"`
	Done    bool   `json:"done"`
}

// Bound JSON bytes, rather than characters: quotes and control characters
// expand during encoding, and filenames may contain multibyte characters.
func widgetText(s string, budget int) string {
	runes := []rune(strings.ToValidUTF8(s, "�"))
	originalLength := len(runes)
	if len(runes) > budget {
		runes = runes[:budget]
	}
	for len(runes) > 0 {
		candidate := string(runes)
		if len(runes) < originalLength {
			candidate += "…"
		}
		encoded, _ := json.Marshal(candidate)
		if len(encoded) <= budget {
			return candidate
		}
		runes = runes[:len(runes)-1]
	}
	return ""
}

func (s transferWidgetState) JSON() string {
	s.Name = widgetText(s.Name, 220)
	s.Detail = widgetText(s.Detail, 220)
	s.Phase = widgetText(s.Phase, 40)
	s.Size = widgetText(s.Size, 64)
	s.Speed = widgetText(s.Speed, 40)
	s.ETA = widgetText(s.ETA, 40)
	s.Elapsed = widgetText(s.Elapsed, 40)
	s.DC = widgetText(s.DC, 32)
	s.Percent = max(0, min(100, s.Percent))
	b, _ := json.Marshal(s)
	return string(b)
}

type transferProgressView struct {
	status     *tg.NewMessage
	widget     bool
	mu         sync.Mutex
	state      transferWidgetState
	total      int64
	started    time.Time
	nextEdit   time.Time
	generation uint64
	writeState func(context.Context, string) error
}

// NewTransferProgress shares the same controller with commands in extras.
func NewTransferProgress(m *tg.NewMessage, phase, name string, size int64) (*transferProgressView, error) {
	return newTransferProgress(m, phase, name, size)
}

func (v *transferProgressView) Status() *tg.NewMessage { return v.status }

// BeginPhase invalidates late callbacks from the preceding transfer stage.
func (v *transferProgressView) BeginPhase(ctx context.Context, phase string, total int64) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.state.Done || ctx.Err() != nil {
		return ctx.Err()
	}
	v.generation++
	v.total = total
	v.state.Phase, v.state.Percent = phase, 0
	v.state.Speed, v.state.ETA, v.state.DC, v.state.Detail = "", "", "", ""
	v.state.Part, v.state.Parts = 0, 0
	v.state.Size = HumanBytes(uint64(max(0, total)))
	v.nextEdit = time.Time{}
	if !v.widget {
		return nil
	}
	editCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	return v.writeState(editCtx, v.state.JSON())
}

func isTransferWidget(m *tg.NewMessage) bool {
	if m == nil || m.Message == nil {
		return false
	}
	_, ok := m.Media().(*tg.MessageMediaWidget)
	return ok
}

func widgetUnavailable(err error) bool {
	for _, code := range []string{"INPUT_MEDIA_WIDGET_NOT_ALLOWED", "MEDIA_INVALID", "CHAT_SEND_INLINE_FORBIDDEN", "CHAT_SEND_MEDIA_FORBIDDEN"} {
		if tg.MatchError(err, code) {
			return true
		}
	}
	return false
}

func newTransferProgress(m *tg.NewMessage, phase, name string, size int64) (*transferProgressView, error) {
	v := &transferProgressView{total: size, started: time.Now(), nextEdit: time.Now().Add(5 * time.Second),
		state: transferWidgetState{Phase: phase, Name: name, Size: HumanBytes(uint64(max(0, size)))}}
	caption := phase + " " + transferCaption(widgetText(name, 220)) + ". Reply with /cancel to stop."
	status, err := transferMessageCall(context.Background(), func() (*tg.NewMessage, error) {
		return m.ReplyMedia(&tg.InputMediaWidget{AllowQueries: true, Width: 340, Height: 0, Html: transferWidgetHTML, ChatData: v.state.JSON()}, &tg.MediaOptions{Caption: caption, ParseMode: tg.HTML})
	})
	if err != nil {
		// An explicit rejection is safe to retry as text; a timeout may have
		// delivered the widget already. Do not send a duplicate in that case.
		if !widgetUnavailable(err) {
			return nil, err
		}
		m.Client.Log.Debug("widget unavailable; using text progress: %v", err)
		status, err = transferMessageCall(context.Background(), func() (*tg.NewMessage, error) { return m.Reply(caption, &tg.SendOptions{ParseMode: tg.HTML}) })
		if err != nil {
			return nil, err
		}
	}
	v.status, v.widget = status, isTransferWidget(status)
	v.writeState = func(ctx context.Context, data string) error {
		_, err := status.Client.MakeRequest(ctx, &tg.MessagesEditMessageWidgetDataParams{Peer: status.Peer, ID: status.ID, ChatData: data})
		if tg.MatchError(err, "MESSAGE_NOT_MODIFIED") {
			return nil
		}
		return err
	}
	return v, nil
}

func (v *transferProgressView) Progress(ctx context.Context, offset, part, parts int64, fileDC ...int) *tg.ProgressManager {
	if !v.widget {
		return TransferProgress(v.status, fileDC...)
	}
	v.mu.Lock()
	v.state.Part, v.state.Parts = part, parts
	generation := v.generation
	v.mu.Unlock()
	client := v.status.Client
	if s := transferForContext(client, ctx); s != nil {
		if user, ok := s.user.(*tg.Client); ok {
			client = user
		}
	}
	dc, label := client.GetDC(), "Upload DC"
	if len(fileDC) > 0 {
		dc, label = fileDC[0], "File DC"
	}
	dcText := label + ": unknown"
	if dc > 0 {
		dcText = fmt.Sprintf("%s: %d", label, dc)
	}
	return tg.NewProgressManager(5).WithCallback(func(info *tg.ProgressInfo) {
		v.updateProgress(ctx, info, offset, part, parts, dcText, generation)
	})
}

func (v *transferProgressView) updateProgress(ctx context.Context, info *tg.ProgressInfo, offset, part, parts int64, dc string, generation ...uint64) {
	if info == nil || ctx.Err() != nil {
		return
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.state.Done || ctx.Err() != nil || part < v.state.Part || (len(generation) > 0 && generation[0] != v.generation) {
		return
	}
	v.state.Part, v.state.Parts, v.state.DC = part, parts, dc
	current := min(v.total, max(0, offset+info.Current))
	if v.total > 0 {
		v.state.Percent = int(float64(current) / float64(v.total) * 100)
	}
	v.state.Size = fmt.Sprintf("%s / %s", HumanBytes(uint64(max(0, current))), HumanBytes(uint64(max(0, v.total))))
	v.state.Speed, v.state.ETA = info.SpeedString(), info.ETAString()
	v.state.Elapsed = time.Since(v.started).Round(time.Second).String()
	if len(dc) > 0 && strings.HasPrefix(dc, "File") {
		v.state.Phase = "Downloading"
	} else {
		v.state.Phase = "Uploading"
	}
	if info.Phase == "finalizing" || current == v.total {
		v.state.Phase = "Finalizing"
	}
	if time.Now().Before(v.nextEdit) {
		return
	}
	v.nextEdit = time.Now().Add(5 * time.Second)
	updateCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if err := v.writeState(updateCtx, v.state.JSON()); err != nil {
		if wait := tg.GetFloodWait(err); wait > 0 {
			v.nextEdit = time.Now().Add(max(5*time.Second, time.Duration(wait)*time.Second+250*time.Millisecond))
		}
	}
}

func (v *transferProgressView) finishState(phase, detail string) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.state.Done {
		return nil
	}
	v.state.Done = true
	v.state.Phase, v.state.Detail = phase, detail
	v.state.Elapsed = time.Since(v.started).Round(time.Second).String()
	v.state.Speed, v.state.ETA = "", ""
	if phase == "Completed" {
		v.state.Percent = 100
		v.state.Size = HumanBytes(uint64(max(0, v.total)))
		v.state.Part = v.state.Parts
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	_, err := transferMessageCall(ctx, func() (bool, error) { return true, v.writeState(ctx, v.state.JSON()) })
	return err
}

func (v *transferProgressView) Finish(phase, detail, caption string) error {
	var stateErr error
	if v.widget {
		stateErr = v.finishState(phase, detail)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	_, editErr := transferMessageCall(ctx, func() (*tg.NewMessage, error) { return v.status.Edit(caption, &tg.SendOptions{ParseMode: tg.HTML}) })
	return errors.Join(stateErr, editErr)
}

func (v *transferProgressView) UploadFailure(err error) error {
	if !v.widget {
		return uploadFailure(v.status, err)
	}
	phase, detail := "Failed", widgetText(err.Error(), 220)
	if errors.Is(err, context.Canceled) {
		phase, detail = "Cancelled", "Completed parts remain available."
	}
	v.status.Client.Log.Error("upload stopped: %v", err)
	return v.Finish(phase, detail, "Upload "+strings.ToLower(phase)+": "+html.EscapeString(detail))
}

// Telegram supplies the authenticated user and original peer/message. Never
// accept an owner or transfer ID supplied by the widget's JavaScript.
func cancelWidgetTransfer(q *tg.UpdateBotWidgetQuery) (bool, string) {
	if _, ok := q.QueryType.(*tg.WidgetQueryTypeData); !ok || string(q.Data) != "filecancel" {
		return false, "Invalid transfer request."
	}
	var chat int64
	switch peer := q.Peer.(type) {
	case *tg.PeerUser:
		chat = peer.UserID
	case *tg.PeerChat:
		chat = peer.ChatID
	case *tg.PeerChannel:
		chat = peer.ChannelID
	default:
		return false, "Invalid transfer chat."
	}
	cancelMutex.RLock()
	active, exists := downloadCancels[fileTransferKey{chat, q.MsgID}]
	cancelMutex.RUnlock()
	if !exists {
		return false, "This transfer has already finished."
	}
	if q.UserID != active.owner && q.UserID != OwnerId {
		return false, "Only the sender or bot owner can cancel this transfer."
	}
	active.cancel()
	return true, "Cancellation requested."
}

func transferWidgetQuery(update tg.Update, c *tg.Client) error {
	q, ok := update.(*tg.UpdateBotWidgetQuery)
	if !ok || string(q.Data) != "filecancel" {
		return nil
	}
	accepted, message := cancelWidgetTransfer(q)
	result, _ := json.Marshal(struct {
		OK      bool   `json:"ok"`
		Message string `json:"message"`
	}{accepted, message})
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_, err := c.MakeRequest(ctx, &tg.MessagesSetBotWidgetQueryAnswerParams{QueryID: q.QueryID, Result: string(result)})
	return err
}
