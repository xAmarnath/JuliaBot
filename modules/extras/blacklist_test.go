package extras

import (
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"main/modules"
	"main/modules/db"

	tg "github.com/xAmarnath/gogram/telegram"
)

func TestBlacklistMediaMatchesAfterResend(t *testing.T) {
	for _, fileType := range []int32{2, 3, 4, 5, 8, 9, 10, 13} {
		t.Run(fmt.Sprint(fileType), func(t *testing.T) {
			const id int64 = 9876543210123456
			for _, size := range []int{20, 28} {
				data := make([]byte, size)
				binary.LittleEndian.PutUint32(data, uint32(fileType)|4<<24)
				binary.LittleEndian.PutUint64(data[4:], uint64(id))
				binary.LittleEndian.PutUint64(data[12:], 1234567)
				fileID := base64.RawURLEncoding.EncodeToString(data)
				media, err := tg.ResolveBotFileID(fileID)
				if err != nil {
					t.Fatal(err)
				}
				st := &blacklistState{media: map[int64]bool{fileIDUniqueID(fileID): true}}
				m := &tg.NewMessage{Message: &tg.MessageObj{Media: media}}
				for _, caption := range []string{"", "a caption", "/a_command"} {
					m.Message.Message = caption
					if kind, match := st.match(m); !match || kind != "media" {
						t.Fatalf("size %d, caption %q: media did not match", size, caption)
					}
				}
				if photo := m.Photo(); photo != nil {
					photo.AccessHash++
					photo.FileReference = []byte("refreshed reference")
				} else {
					m.Document().AccessHash++
					m.Document().FileReference = []byte("refreshed reference")
				}
				m.Message.FwdFrom = &tg.MessageFwdHeader{}
				m.Message.EditDate = 123
				m.Message.GroupedID = 456
				if _, match := st.match(m); !match {
					t.Fatal("forwarded/edited album media with a refreshed reference did not match")
				}
				if photo := m.Photo(); photo != nil {
					photo.ID++
				} else {
					m.Document().ID++
				}
				if _, match := st.match(m); match {
					t.Fatal("a different upload matched the blocked file")
				}
			}
		})
	}
}

func TestBlacklistLegacyMediaID(t *testing.T) {
	for _, data := range []string{"8_4_987654321_12345678", "8_4_987654321_123456789", "8_4_987654321_123456789_4096", "8_4_987654321_123456789_123456"} {
		for _, encoding := range []*base64.Encoding{base64.RawURLEncoding, base64.URLEncoding} {
			fileID := encoding.EncodeToString([]byte(data))
			if got := fileIDUniqueID(fileID); got != 987654321 {
				t.Fatalf("legacy ID with decoded length %d decoded as %d", len(data), got)
			}
		}
	}
	for _, data := range []string{"", "invalid!", base64.RawURLEncoding.EncodeToString([]byte("garbage")), base64.RawURLEncoding.EncodeToString([]byte("8_4_987654321_broken")), base64.RawURLEncoding.EncodeToString([]byte("8_4_987654321_1_bad")), base64.RawURLEncoding.EncodeToString([]byte("99_4_987654321_1234567"))} {
		if got := fileIDUniqueID(data); got != 0 {
			t.Fatalf("invalid ID decoded as %d", got)
		}
	}
}

func TestBlacklistCaptionAndUnsupportedMedia(t *testing.T) {
	word, err := compileTrigger("blocked")
	if err != nil {
		t.Fatal(err)
	}
	st := &blacklistState{media: map[int64]bool{123: true}, triggers: []*trigger{word}}
	for _, media := range []tg.MessageMedia{nil, &tg.MessageMediaEmpty{}, &tg.MessageMediaPhoto{Photo: &tg.PhotoEmpty{ID: 123}}, &tg.MessageMediaDocument{Document: &tg.DocumentEmpty{ID: 123}}} {
		m := &tg.NewMessage{Message: &tg.MessageObj{Media: media}}
		if _, match := st.match(m); match {
			t.Fatalf("unsupported media matched: %T", media)
		}
		m.Message.Message = "a BLOCKED caption"
		if kind, match := st.match(m); !match || kind != "blocked" {
			t.Fatalf("caption was not checked for %T", media)
		}
	}
	for _, m := range []*tg.NewMessage{nil, {}, {Message: &tg.MessageObj{}}} {
		if mediaUniqueID(m) != 0 {
			t.Fatal("empty message has a media ID")
		}
	}
}

func TestBlacklistWatcherIgnoresNonGroupAndOutgoingMessages(t *testing.T) {
	for _, m := range []*tg.NewMessage{
		nil, {},
		{Message: &tg.MessageObj{PeerID: &tg.PeerUser{UserID: 123}}},
		{Message: &tg.MessageObj{Out: true, PeerID: &tg.PeerChannel{ChannelID: 123}}},
		{Message: &tg.MessageObj{PeerID: &tg.PeerChannel{ChannelID: 123}}, Channel: &tg.Channel{Broadcast: true}},
	} {
		if err := BlacklistWatcher(m); err != nil {
			t.Fatal(err)
		}
	}
}

func TestBlacklistWatcherDeletesBeforeCheckingAdminStatus(t *testing.T) {
	const chatID int64 = 77123
	word, err := compileTrigger("blocked")
	if err != nil {
		t.Fatal(err)
	}
	blacklistMu.Lock()
	previous, existed := blacklistCache[chatID]
	blacklistMu.Unlock()
	t.Cleanup(func() {
		blacklistMu.Lock()
		defer blacklistMu.Unlock()
		if existed {
			blacklistCache[chatID] = previous
		} else {
			delete(blacklistCache, chatID)
		}
	})
	for _, action := range []db.BlacklistAction{db.ActionDelete, db.ActionBan, db.ActionMute} {
		blacklistMu.Lock()
		blacklistCache[chatID] = &blacklistState{
			at: time.Now(), ttl: time.Minute, media: map[int64]bool{123: true},
			triggers: []*trigger{word}, settings: db.BlacklistSettings{Action: action},
		}
		blacklistMu.Unlock()
		for _, sender := range []tg.Peer{
			&tg.PeerChannel{ChannelID: chatID},
			&tg.PeerUser{UserID: modules.AnonBotID},
			&tg.PeerUser{UserID: 456},
		} {
			for _, media := range []bool{false, true} {
				m := &tg.NewMessage{ID: 42, Client: &tg.Client{}, Peer: &tg.InputPeerChat{}, Message: &tg.MessageObj{
					ID: 42, PeerID: &tg.PeerChannel{ChannelID: chatID}, FromID: sender, Message: "blocked",
				}}
				if media {
					m.Message.Message = ""
					m.Message.Media = &tg.MessageMediaDocument{Document: &tg.DocumentObj{ID: 123}}
				}
				err := BlacklistWatcher(m)
				if err == nil || !strings.Contains(err.Error(), "blacklist: delete message 42") || errors.Unwrap(err) == nil {
					t.Fatalf("action %s, sender %T, media %v: expected contextual deletion error, got %v", action, sender, media, err)
				}
				m.Message.Message = "allowed"
				m.Message.Media = nil
				if err := BlacklistWatcher(m); err != nil {
					t.Fatalf("non-matching message was deleted: %v", err)
				}
			}
		}
	}
}
