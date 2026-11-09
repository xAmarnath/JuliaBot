package modules

import (
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	"time"

	tg "github.com/xAmarnath/gogram/telegram"
)

//go:embed inline_widget.html
var inlineWidgetHTML string

const inlineWidgetTestID = "juliabot-widget-test-v1"

func inlineWidgetTest(i *tg.InlineQuery) error {
	i.Client.Log.Info("[widget-inline] query received id=%d peer=%T", i.QueryID, i.PeerType)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_, err := i.Client.MakeRequest(ctx, &tg.MessagesSetInlineBotResultsParams{
		QueryID: i.QueryID, Private: true, CacheTime: 0,
		Results: []tg.InputBotInlineResult{&tg.InputBotInlineResultObj{
			ID: inlineWidgetTestID, Type: "article", Title: "JuliaBot HTML widget test",
			Description: "Send a widget and test a live state update.",
			SendMessage: &tg.InputBotInlineMessageWidget{
				AllowQueries: true, Width: 340, Height: 0, Html: inlineWidgetHTML,
				ChatData: `{"message":"Waiting for a state update."}`,
				Message:  "JuliaBot inline widget test. Tap Test state update in the card.",
			},
		}},
	})
	if err != nil {
		i.Client.Log.Error("[widget-inline] result rejected id=%d: %v", i.QueryID, err)
		return err
	}
	i.Client.Log.Info("[widget-inline] result accepted id=%d", i.QueryID)
	return nil
}

func inlineWidgetTestChosen(update tg.Update, c *tg.Client) error {
	q, ok := update.(*tg.UpdateBotInlineSend)
	if ok && q.ID == inlineWidgetTestID {
		c.Log.Info("[widget-inline] result chosen (feedback received)")
	}
	return nil
}

func inlineWidgetTestQuery(update tg.Update, c *tg.Client) error {
	q, ok := update.(*tg.UpdateInlineBotWidgetQuery)
	if !ok || string(q.Data) != "inline-widget-test" {
		return nil
	}
	c.Log.Info("[widget-inline] button query received id=%d chat_type=%s", q.QueryID, q.ChatType)
	message := "Invalid test request."
	if _, valid := q.QueryType.(*tg.WidgetQueryTypeData); valid {
		data, _ := json.Marshal(map[string]string{"message": "Bot updated this card at " + time.Now().UTC().Format("15:04:05.000 UTC")})
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		editErr := editInlineWidgetTestState(ctx, c, q.InlineMessageID, string(data))
		cancel()
		message = "State updated for everyone viewing this message."
		if editErr != nil {
			message = "Telegram rejected the state update. Check the bot logs."
			c.Log.Error("[widget-inline] state edit rejected id=%d: %v", q.QueryID, editErr)
		} else {
			c.Log.Info("[widget-inline] state edit accepted id=%d", q.QueryID)
		}
	}
	result, _ := json.Marshal(map[string]string{"message": message})
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_, err := c.MakeRequest(ctx, &tg.MessagesSetBotWidgetQueryAnswerParams{QueryID: q.QueryID, Result: string(result)})
	if err != nil {
		c.Log.Error("[widget-inline] answer rejected id=%d: %v", q.QueryID, err)
	}
	return err
}

func editInlineWidgetTestState(ctx context.Context, c *tg.Client, id tg.InputBotInlineMessageID, data string) error {
	var dc int32
	switch msg := id.(type) {
	case *tg.InputBotInlineMessageID64:
		dc = msg.DcID
	case *tg.InputBotInlineMessageIDObj:
		dc = msg.DcID
	default:
		return fmt.Errorf("unsupported inline message ID: %T", id)
	}
	// Inline messages can belong to a different DC from the bot's session.
	sender := c.MTProto
	if dc != int32(c.GetDC()) {
		var err error
		sender, err = c.CreateExportedSender(ctx, int(dc), false, false)
		if err != nil {
			return err
		}
		defer sender.Terminate()
	}
	_, err := sender.MakeRequest(ctx, &tg.MessagesEditInlineBotMessageWidgetDataParams{ID: id, ChatData: data})
	return err
}
