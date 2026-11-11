package main

import (
	"context"
	"io"
	"log"
	"main/modules"
	"main/modules/db"
	"main/modules/extras"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	_ "github.com/joho/godotenv/autoload"
	tg "github.com/xAmarnath/gogram/telegram"

	_ "net/http/pprof"
)

var ownerId int64 = 0
var LoadModules = os.Getenv("ENV") != "development"

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	markReady := startHealthServer(ctx)
	logZap, err := os.OpenFile("log.log", os.O_RDWR|os.O_CREATE|os.O_APPEND, 0666)
	if err != nil {
		log.Fatal(err)
	}

	defer logZap.Close()
	wr := io.MultiWriter(os.Stdout, logZap)

	if _, err := db.GetDB(); err != nil {
		log.Fatalf("initialize database: %v", err)
	}
	defer db.CloseDB()
	socks := buildSocksProxy()

	appId, _ := strconv.Atoi(os.Getenv("APP_ID"))
	ownerId, _ = strconv.ParseInt(os.Getenv("OWNER_ID"), 10, 64)
	clientCfg := tg.ClientConfig{
		AppID:         int32(appId),
		AppHash:       os.Getenv("APP_HASH"),
		LogLevel:      tg.LogInfo,
		MemorySession: true,
		SessionName:   "xyumi-bot",
	}
	if socks != nil {
		clientCfg.Proxy = socks
	}
	client, err := tg.NewClient(clientCfg)
	if err != nil {
		panic(err)
	}

	defer client.Terminate()
	if _, err := client.Conn(); err != nil {
		log.Fatal(err)
	}
	client.Log.SetOutput(wr)
	if err := client.LoginBot(os.Getenv("BOT_TOKEN")); err != nil {
		log.Fatal(err)
	}
	if client.Me() == nil || !client.Me().Bot {
		log.Fatal("BOT_TOKEN must identify the main bot")
	}
	modules.InitClient(client)
	var transferUser *tg.Client
	if session := strings.TrimSpace(os.Getenv("USER_SESSION")); session != "" {
		userCfg := tg.ClientConfig{AppID: int32(appId), AppHash: os.Getenv("APP_HASH"),
			StringSession: session, MemorySession: true, SessionName: "transfer-user", LogLevel: tg.LogInfo,
			DisableCache: true}
		if socks != nil {
			userCfg.Proxy = socks
		}
		transferUser, err = tg.NewClient(userCfg)
		if err != nil {
			log.Fatalf("initialize USER_SESSION: %v", err)
		}
		defer transferUser.Terminate()
		transferUser.Log.SetOutput(wr)
		if _, err := transferUser.Conn(); err != nil {
			log.Fatalf("connect USER_SESSION: %v", err)
		}
		if _, err := transferUser.GetMe(); err != nil {
			log.Fatalf("authenticate USER_SESSION: %v", err)
		}
		if err := modules.InitTransfers(ctx, client, transferUser); err != nil {
			log.Fatal(err)
		}
		if me := transferUser.Me(); me != nil {
			client.Log.Info("User transfers enabled (premium=%v)", me.Premium)
		}
	}
	defer modules.CloseTransfers()

	me, err := client.GetMe()
	if err != nil {
		log.Fatalf("get bot identity: %v", err)
	}
	client.Logger.Info("Bot is running as @%s", me.Username)
	go func() {
		log.Println("Pprof server starting on :9009")
		if err := http.ListenAndServe(":9009", nil); err != nil {
			log.Printf("Pprof server error: %v", err)
		}
	}()

	modules.SetupFilters(ownerId, LoadModules)
	extras.AvatarServerInit(client)
	modules.RegisterHandlers()
	stopStatistics := extras.StartStatistics()
	if err := extras.StartGame(ctx); err != nil {
		log.Fatalf("initialize game: %v", err)
	}
	markReady()
	if LoadModules {
		extras.StartKissWatch(ctx)
	}
	go http.ListenAndServe("localhost:6060", nil)
	go func() {
		<-ctx.Done()
		modules.CloseTransfers()
		if transferUser != nil {
			_ = transferUser.Terminate()
		}
		_ = client.Stop()
	}()
	client.Idle()
	modules.FlushLastSeen()
	extras.FlushGame()
	stopStatistics()
	db.CloseDB()

	client.Logger.Info("Bot stopped")
}

func buildSocksProxy() *tg.Socks5Proxy {
	raw := strings.TrimSpace(os.Getenv("PROXY"))
	if raw == "" {
		return nil
	}
	host, portStr, err := net.SplitHostPort(raw)
	if err != nil {
		log.Printf("[proxy] invalid PROXY=%q (expected host:port): %v", raw, err)
		return nil
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		log.Printf("[proxy] invalid port in PROXY=%q: %v", raw, err)
		return nil
	}
	log.Printf("[proxy] using socks5 %s:%d", host, port)
	return &tg.Socks5Proxy{
		BaseProxy: tg.BaseProxy{Host: host, Port: port},
		Username:  os.Getenv("PROXY_USERNAME"),
		Password:  os.Getenv("PROXY_PASSWORD"),
	}
}

// Heroku keeps one web dyno for the bot; the Mini App has been removed.
func startHealthServer(ctx context.Context) func() {
	port := os.Getenv("PORT")
	if port == "" {
		return func() {}
	}
	var ready atomic.Bool
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		if !ready.Load() {
			http.Error(w, "JuliaBot is starting.", http.StatusServiceUnavailable)
			return
		}
		_, _ = io.WriteString(w, "JuliaBot is running.\n")
	})
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		if !ready.Load() {
			http.Error(w, "starting", http.StatusServiceUnavailable)
			return
		}
		_, _ = io.WriteString(w, "ok\n")
	})
	server := &http.Server{Addr: ":" + port, Handler: mux, ReadHeaderTimeout: 5 * time.Second, IdleTimeout: 30 * time.Second}
	go func() {
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Printf("health server: %v", err)
		}
	}()
	go func() {
		<-ctx.Done()
		timeout, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = server.Shutdown(timeout)
	}()
	return func() { ready.Store(true) }
}
