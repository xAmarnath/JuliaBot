package extras

import (
	"fmt"
	"html"
	"image"
	_ "image/jpeg"
	_ "image/png"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	tg "github.com/xAmarnath/gogram/telegram"
	modules "main/modules"
)

type avatarTarget struct {
	UserID    int64
	FirstName string
	LastName  string
	Username  string
	Photo     tg.UserProfilePhoto
}

func avatarFromUser(u *tg.UserObj) avatarTarget {
	return avatarTarget{UserID: u.ID, FirstName: u.FirstName, LastName: u.LastName, Username: u.Username, Photo: u.Photo}
}

// avatarResolveTarget picks the replied user, then an @username/ID argument, then the sender.
func avatarResolveTarget(m *tg.NewMessage) (avatarTarget, error) {
	if m.IsReply() {
		if reply, err := m.GetReplyMessage(); err == nil && reply != nil && reply.SenderID() != 0 {
			if u, uerr := m.Client.GetUser(reply.SenderID()); uerr == nil && u != nil {
				return avatarFromUser(u), nil
			}
			return avatarTarget{UserID: reply.SenderID(), FirstName: "User"}, nil
		}
	}

	if args := strings.Fields(m.Args()); len(args) > 0 {
		token := strings.TrimPrefix(args[0], "@")
		if n, err := strconv.ParseInt(token, 10, 64); err == nil {
			if u, uerr := m.Client.GetUser(n); uerr == nil && u != nil {
				return avatarFromUser(u), nil
			}
			return avatarTarget{}, fmt.Errorf("could not resolve user %d", n)
		}
		peer, err := m.Client.ResolvePeer(token)
		if err != nil {
			return avatarTarget{}, fmt.Errorf("could not resolve @%s", token)
		}
		if _, ok := peer.(*tg.InputPeerUser); !ok {
			return avatarTarget{}, fmt.Errorf("@%s is not a user", token)
		}
		id := m.Client.GetPeerID(peer)
		if u, uerr := m.Client.GetUser(id); uerr == nil && u != nil {
			return avatarFromUser(u), nil
		}
		return avatarTarget{UserID: id, FirstName: token}, nil
	}

	if m.Sender != nil {
		return avatarFromUser(m.Sender), nil
	}
	return avatarTarget{UserID: m.SenderID(), FirstName: "User"}, nil
}

func avatarDownload(c *tg.Client, info avatarTarget) (string, error) {
	if info.Photo == nil {
		return "", fmt.Errorf("user has no profile photo")
	}
	var hash int64
	if peer, err := c.ResolvePeer(info.UserID); err == nil {
		if pu, ok := peer.(*tg.InputPeerUser); ok {
			hash = pu.AccessHash
		}
	}
	full, err := c.UsersGetFullUser(&tg.InputUserObj{UserID: info.UserID, AccessHash: hash})
	if err != nil || full == nil {
		return "", fmt.Errorf("could not fetch the user's profile")
	}
	uf := full.FullUser
	var photo tg.Photo
	switch {
	case uf.ProfilePhoto != nil:
		photo = uf.ProfilePhoto
	case uf.PersonalPhoto != nil:
		photo = uf.PersonalPhoto
	case uf.FallbackPhoto != nil:
		photo = uf.FallbackPhoto
	}
	p, ok := photo.(*tg.PhotoObj)
	if !ok || p == nil {
		return "", fmt.Errorf("user has no visible profile photo")
	}
	tmp := filepath.Join(os.TempDir(), fmt.Sprintf("avatar_dl_%d_%d.jpg", info.UserID, time.Now().UnixNano()))
	got, err := modules.TransferDownloadMedia(c, p, &tg.DownloadOptions{FileName: tmp})
	if err != nil {
		os.Remove(tmp)
		return "", err
	}
	if got != "" && got != tmp {
		os.Remove(tmp)
		return got, nil
	}
	return tmp, nil
}

func avatarFormatBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for x := n / unit; x >= unit; x /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.2f %ciB", float64(n)/float64(div), "KMGTPE"[exp])
}

func avatarImageDimensions(path string) (int, int) {
	f, err := os.Open(path)
	if err != nil {
		return 0, 0
	}
	defer f.Close()
	cfg, _, err := image.DecodeConfig(f)
	if err != nil {
		return 0, 0
	}
	return cfg.Width, cfg.Height
}

func AvatarHandler(m *tg.NewMessage) error {
	status, _ := m.Reply("fetching avatar...")

	info, err := avatarResolveTarget(m)
	if err != nil {
		if status != nil {
			status.Edit("failed: " + html.EscapeString(err.Error()))
		}
		return nil
	}

	if info.UserID == 0 {
		if status != nil {
			status.Edit("could not resolve user")
		}
		return nil
	}

	path, err := avatarDownload(m.Client, info)
	if err != nil {
		if status != nil {
			status.Edit("failed: " + html.EscapeString(err.Error()))
		}
		return nil
	}
	defer os.Remove(path)

	st, serr := os.Stat(path)
	var size int64
	if serr == nil {
		size = st.Size()
	}
	w, h := avatarImageDimensions(path)

	displayName := strings.TrimSpace(info.FirstName + " " + info.LastName)
	if displayName == "" {
		displayName = "User"
	}

	caption := fmt.Sprintf("<b>%s</b>", html.EscapeString(displayName))
	if info.Username != "" {
		caption += fmt.Sprintf("\n@%s", html.EscapeString(info.Username))
	}
	caption += fmt.Sprintf("\n<code>%d</code>", info.UserID)
	if w > 0 && h > 0 {
		caption += fmt.Sprintf("\n<b>Size:</b> <code>%s</code>  <b>Dim:</b> <code>%dx%d</code>", avatarFormatBytes(size), w, h)
	} else {
		caption += fmt.Sprintf("\n<b>Size:</b> <code>%s</code>", avatarFormatBytes(size))
	}

	_, merr := modules.TransferReplyMedia(m, path, &tg.MediaOptions{
		Caption:  caption,
		FileName: fmt.Sprintf("avatar_%d.jpg", info.UserID),
		MimeType: "image/jpeg",
	})
	if merr != nil {
		if status != nil {
			status.Edit("upload failed: " + html.EscapeString(merr.Error()))
		}
		return nil
	}
	if status != nil {
		status.Delete()
	}
	return nil
}

func registerAvatarHandlers() {
	c := modules.Client
	modules.OnCommand(c, "cmd:avatar", AvatarHandler)
}

func init() {
	modules.QueueHandlerRegistration(registerAvatarHandlers)
}
