package modules

import (
	"fmt"
	tg "github.com/xAmarnath/gogram/telegram"
)

const boiler_code_for_eval = `
package main

import (
	"bufio"
	"fmt"
	"os"
	tg "github.com/xAmarnath/gogram/telegram"
)

%s

var msgID int32 = %d
var chatID int64 = %d
var chatPeer tg.InputPeer = %s
var cacheJSON string

var client *tg.Client
var message *tg.NewMessage
var m *tg.NewMessage
var r *tg.NewMessage

func evalCode() {
	%s
}

func readStdinValue(reader *bufio.Reader) (string, error) {
	s, err := reader.ReadString('\x00')
	if err != nil {
		return "", err
	}
	return s[:len(s)-1], nil
}

func main() {
	reader := bufio.NewReader(os.Stdin)
	sessionString, err := readStdinValue(reader)
	if err != nil {
		fmt.Println("Failed to read eval session:", err)
		return
	}
	cacheJSON, err = readStdinValue(reader)
	if err != nil {
		fmt.Println("Failed to read eval cache:", err)
		return
	}

	client, err = tg.NewClient(tg.ClientConfig{
		StringSession: sessionString,
		MemorySession: true,
		Cache: tg.NewCache("", &tg.CacheConfig{Memory: true, LogLevel: tg.LogDisable}),
		LogLevel:      tg.LogDisable,
	})
	if err != nil {
		fmt.Println("Client error:", err)
		return
	}

	defer client.Terminate()

	if cacheJSON != "" {
		if err := client.Cache.ImportJSON([]byte(cacheJSON)); err != nil {
			fmt.Println("Failed to import eval cache:", err)
			return
		}
	}

	if _, err := client.Conn(); err != nil {
		fmt.Println("Connection error:", err)
		return
	}

	msgs, err := client.GetMessages(chatPeer, &tg.SearchOption{
		IDs: int(msgID),
	})
	if err != nil {
		fmt.Println("Failed to get message:", err)
		return
	}

	if len(msgs) == 0 {
		fmt.Println("Failed to get message: command message was not returned")
		return
	}

	message = &msgs[0]
	m = message
	r, _ = message.GetReplyMessage()

	fmt.Println("output-start")
	evalCode()
}
`

// evalPeerLiteral carries the message's peer type and access hash into the child
// process, so fetching the command does not depend on a cache lookup by raw ID.
func evalPeerLiteral(m *tg.NewMessage) (string, error) {
	if m == nil {
		return "", fmt.Errorf("missing eval message")
	}
	peer := m.Peer
	if peer == nil {
		switch {
		case m.Channel != nil:
			peer = &tg.InputPeerChannel{ChannelID: m.Channel.ID, AccessHash: m.Channel.AccessHash}
		case m.Chat != nil:
			peer = &tg.InputPeerChat{ChatID: m.Chat.ID}
		case m.Sender != nil:
			peer = &tg.InputPeerUser{UserID: m.Sender.ID, AccessHash: m.Sender.AccessHash}
		}
	}
	switch p := peer.(type) {
	case *tg.InputPeerChannel:
		if p != nil {
			return fmt.Sprintf("&tg.InputPeerChannel{ChannelID: %d, AccessHash: %d}", p.ChannelID, p.AccessHash), nil
		}
	case *tg.InputPeerChat:
		if p != nil {
			return fmt.Sprintf("&tg.InputPeerChat{ChatID: %d}", p.ChatID), nil
		}
	case *tg.InputPeerUser:
		if p != nil {
			return fmt.Sprintf("&tg.InputPeerUser{UserID: %d, AccessHash: %d}", p.UserID, p.AccessHash), nil
		}
	case *tg.InputPeerSelf:
		if p != nil {
			return "&tg.InputPeerSelf{}", nil
		}
	}
	return "", fmt.Errorf("unsupported eval chat peer %T", peer)
}
