### Sample Modular Bot for [Gogram](https://github.com/xAmarnath/gogram.git)

### ENV

- Create a `.env` file in the root directory of the project

- `BOT_TOKEN` : Telegram Bot Token (@BotFather)
- `APP_ID` : Telegram API ID (my.telegram.org)
- `APP_HASH` : Telegram API hash (my.telegram.org)
- `OWNER_ID` : Telegram User ID of Bot Owner
- `AUTH_USERS`: Additional user IDs allowed to use file commands, separated by commas or spaces.
- `MONGODB_URI`: Required MongoDB connection string, stored as a secret environment variable.
- `MONGODB_DATABASE`: MongoDB database name; defaults to `Main_Database`. Database names cannot contain spaces.
- `USER_SESSION`: Optional gogram user string session for file transfers. The main client always uses `BOT_TOKEN`.
- `UPLOAD_SPLIT_SIZE`: Optional maximum upload part size, such as `1900MiB` or `3GiB`.

### File commands

Only the owner and `AUTH_USERS` can use `/ul`, `/ldl`, `/ariadl`, and `/mirror`.

- `/ldl`: Reply to a Telegram file, or provide a `t.me` message link.
- `/ul filename [--doc] [-s] [--split 1900MiB]`: Upload a file. Files above the active account's Telegram limit are split automatically. `--split` overrides `UPLOAD_SPLIT_SIZE`; parts never exceed the account limit. Splitting reads file sections directly without creating extra local copies.
- `/ariadl URL`: Download an HTTP(S) URL or magnet link through aria2. The result lists paths for `/ul`. Torrent seeding stops when downloading finishes.
- `/mirror`: Download a replied-to file and upload it again, with one cancellation context across both phases.
- Use the Cancel button below transfer progress, or reply with `/cancel`. The transfer's initiator and bot owner can cancel it. Completed split parts remain available after cancellation.

Telegram download progress shows the file's storage DC; upload progress shows the active account's upload DC. `/ul` captions include the upload duration in seconds, including each split part. The split completion message includes the total elapsed time.

`/ul`, `/ldl`, `/mirror`, and `/ariadl` use an HTML widget with live message state (`chat_data`), a progress bar, speed, elapsed time, ETA, and a Cancel button. Split uploads share one progress card; completed files are sent separately. A mirror card follows the download and upload phases through completion. aria2 cards show metadata retrieval, peer connections, seeders, and download progress; downloaded paths remain available for `/ul`. Captions show the outcome for clients without widget rendering, and replying with `/cancel` also works.

`@botusername test` is an experimental inline HTML widget probe. Telegram currently rejects it on production with `INPUT_MEDIA_WIDGET_NOT_ALLOWED`, so no inline result appears. When Telegram enables it, sending the result and tapping **Test state update** updates that message's `chat_data`. `[widget-inline]` logs record the server responses; results are uncached.

The same message state works for every member of a group. However, [Telegram currently restricts production widgets to bot private chats](https://core.telegram.org/bots/widgets#availability). JuliaBot attempts a widget in groups too and falls back to text when Telegram explicitly rejects it. `SharedWidget`/`public_data` share state across messages and forwards; they do not bypass availability restrictions. Full group widgets can be tested on Telegram's test server.

JuliaBot does not request content protection for widgets. Production Telegram nevertheless returns widget messages with `noforwards` enabled, which clients use for forwarding and screenshot protection. There is no bot-side setting to override this production restriction. Companion posters and completed transfer files are ordinary unprotected media and can be forwarded.

Magnet progress shows the torrent name, peer connections, seeders, and whether aria2 is fetching metadata or waiting for file data. aria2 uses an explicit DHT bootstrap address and saves its routing cache on shutdown for reuse during the dyno's lifetime. A known file size does not mean metadata retrieval has finished. Transfers still depend on reachable peers serving the requested content.

When `USER_SESSION` is present, the helper starts the bot in private and handles transfers for /ldl, /ul, and /mirror. Downloads are forwarded into that private chat. Uploads arrive in the bot's private chat, then the bot delivers its own received file reference to the destination chat. Widget progress stays visible in its own message. Telegram determines Premium entitlement from the helper account itself; owning a bot with a Premium account does not give the bot Premium limits. Without `USER_SESSION`, transfers use the bot account.

### IMDb

In private chats, `/imdb` opens a curated cinema browser. Use `/imdb movie name`, `/imdb tt0133093`, or `/imdb https://www.imdb.com/title/tt0133093/` to search or open a title directly. The theme-aware HTML card includes ratings, votes, year, runtime, and certificate, with **Overview**, **Story**, **Cast**, **Facts**, and **Similar** tabs.

Search results and longer details are paginated to fit Telegram's widget height limit. Similar titles load on demand, two per page; **Back** restores the previous title, tab, and page or the original search results. IMDb and trailer links open their official pages. The card uses IMDb's dark surfaces, white text, yellow accents and blue links. Opening a title automatically sends its full-quality poster as a photo replying to the card, once per title per session. If artwork could not load, **View poster** lets you retry. Telegram blocks remote images and limits live state to 1 KB, so posters accompany the card rather than being embedded in it. Loading failures offer Retry and preserve navigation history.

Only the requesting viewer can control a cinema card; stale and invalid actions are rejected. Sessions expire after one hour of inactivity or a restart. Groups retain the existing poster-and-caption browser with inline buttons while production widgets are limited to private chats.

### Media account routing

Only `/ldl`, `/ul`, and `/mirror` opt into `USER_SESSION`. All other commands, including Instagram/TikTok, paste files, IMDb artwork, stickers, avatars, and media conversions, upload and download through the bot. The transfer account's Premium limits apply only to those three file commands.

### Paste

`/paste [-k|-d|-s] text`, or reply to a text message or file of any name, extension, or MIME type (up to 2 MiB). For files with captions, the file contents are pasted. UTF-8 and UTF-16 files are supported, including byte-order marks. Binary files are encoded as base64 without losing their original bytes. The limit applies to the original file size. Providers fall back automatically; dpaste links include a raw-text button and expire after seven days. If every provider is unavailable, the bot returns the content as `paste.txt`.

### Telegram dependency

The app uses the published `github.com/xAmarnath/gogram v1.8.0-beta.15` module. Deployment does not bundle or replace gogram with a local fork.

### Persistence and Heroku

All application settings and saved records use MongoDB, including alerts previously stored in SQLite. Startup requires a working MongoDB connection. Use a replica set or Atlas deployment with transaction support.

Heroku's filesystem is temporary. Downloads, logs, and generated media disappear when the dyno is replaced; MongoDB records remain. Run **one web dyno**, with no workers, to avoid duplicate Telegram sessions and conflicting caches. Configure the Heroku apt buildpack before the Go buildpack. `Aptfile` installs ffmpeg, mediainfo, aria2c, neofetch, and the listed utilities; `Procfile` starts the bot. A small HTTP server binds to `PORT` immediately; `/healthz` returns 503 during startup and 200 after initialization.

The Mini App has been removed. `ARENA_URL` is no longer used. Startup restores the normal Telegram command menu; remove any separately configured Main Mini App in BotFather.

The bot loads MongoDB records into memory at startup. Settings, filters, rules, notes, warnings and other database reads use that cache. Writes commit to MongoDB before the cache changes; readers do not wait for network writes. External database edits require a restart. An unresolved transaction commit stops cached database access until restart, avoiding stale reads or unsafe retries.

Game actions use memory and save dirty players every 15 seconds, with a final save during graceful shutdown. A forced crash can lose changes since the last successful save; failures retain dirty players for retry.

Use `GO_INSTALL_PACKAGE_SPEC=.`, `GOFLAGS=-mod=readonly`, and `GO_INSTALL_TOOLS_IN_IMAGE=true` when deploying with the Go buildpack. Credentials belong in Heroku config vars and must not be included in the source archive.

### Setting up

- Install Go 1.25 or higher

```bash
git clone https://github.com/xAmarnath/JuliaBot.git
cd JuliaBot

go mod tidy
go run .
```


### Docker Setup
```bash
docker build -t julia .
docker run -d --name julia --env-file .env julia
```

### Features

- Modular
- Example Modules
- Easy to use
- Extendable

### Optional Dependencies

- [CairoSVG](https://cairosvg.org/)
    ```bash
    sudo apt-get install cairosvg
    ```

- [FFmpeg](https://ffmpeg.org/)
    ```bash
    sudo apt-get install ffmpeg
    ```

- [Ubuntu Fonts](https://design.ubuntu.com/font/)
    ```bash
    sudo apt install fonts-ubuntu
    ```

- [Vorbis Tools](https://xiph.org/vorbis/)
    ```bash
    sudo apt-get install vorbis-tools
    ```

### License

- [MIT](LICENSE)


### KissKH episode downloads

Use `/kisskh <drama-id, name or URL>` (for example `/kisskh 13907`). Choose a search result, then an episode from the four-column picker. Large episode lists are paged. This command follows the existing file-transfer user authorization.

The module uses `yt-dlp` with eight parallel HLS fragments, then FFmpeg to embed every available decrypted SRT track as selectable MP4 subtitles. It preserves the video/audio streams, adds language labels, and uploads the MP4 as a document with video metadata and a thumbnail. Use a player such as VLC to select embedded subtitles. A failed subtitle decryption stops the job instead of silently dropping that language. The configured transfer account handles uploads when available; the bot delivers the final file. Only one episode download runs at a time; the progress message includes Cancel.

Required tools: `yt-dlp`, `ffmpeg`, and `ffprobe` (included in Docker and the Heroku Aptfile). Downloads are temporary and removed when the job finishes or fails. API/key generation depends on `kisskh.is` and `enc-dec.app`.

### Sticker and upload fixes

`.kang` accepts Telegram photos and image documents, scales static images to a 512-pixel longest edge while preserving aspect ratio/transparency, and verifies Telegram's size limits. New default pack names use a `v2_` prefix and retry later versions if occupied; existing saved packs remain usable.

If Telegram rejects replacing an upload progress message with media (`MEDIA_NEW_INVALID`), the bot sends a new media message using its own received reference and removes the progress message after successful delivery.


### KissKH downloads and shared watchlist

- `/kisskh <ID, URL or name>` is public. Episode picker and cancellation remain requester-only (the bot owner can also cancel). Downloads share one slot.
- Bot owner and `AUTH_USERS` manage the singleton watchlist: `/kisswatch add <ID, URL or name>`, `/kisswatch list`, `/kisswatch remove <ID>`.
- `/kisschannel <channel ID or @username>` sets the one shared broadcast channel; the bot needs Post Messages permission. `KISSKH_WATCH_CHANNEL` can initialize an empty configuration.
- Every watched drama is checked every 30 minutes. Existing episodes are baselined when added; future episodes are downloaded with all available selectable subtitles, poster JPEG thumbnail, filename/video attributes, and delivered by the bot through the existing optional user-account relay. Video-frame thumbnails are used if a poster cannot be fetched.
- MongoDB persists configuration and per-episode delivery state. Interrupted downloads retry; ambiguous interrupted uploads wait for review to avoid duplicates. After checking the channel, an admin can use `/kisswatch retry <drama ID> <episode ID>`.
- One worker is started per bot process. Run only one worker instance. No full-episode downloads are needed for automated tests.


### Simple game

`/game`, `/daily`, `/battle`, `/fight`, `/shop`, `/buy`, `/fighters`, `/equip`, `/upgrade`, and `/lb` provide daily streaks, quick battles, fighters and leaderboards. PvP challenges require the other player's acceptance, expire after five minutes, and have no wagers. Battles have a 90-second cooldown. Existing balances and fighters survive the update; retired inventories remain in saved data, and unfinished duel escrow is returned once. Estates, spells, replays and the Mini App are no longer exposed.

### Greetings and verification

Use `/setwelcome` and `/setgoodbye` with text or a reply to media. Templates support `{first}`, `{last}`, `{fullname}`, `{username}`, `{mention}`, `{id}` and `{chatname}`, plus inline link buttons. Changing a template preserves cleanup settings.

- `/welcome on|off`, `/goodbye on|off`: enable or disable greetings.
- `/testwelcome`, `/testgoodbye`: preview without deleting previous greetings or starting timers.
- `/cleanwelcome on|off`, `/cleangoodbye on|off`: delete the previous greeting after a replacement sends successfully.
- `/wautodelete 30s|off`, `/gautodelete 30s|off`: delete after 5 seconds to 24 hours.
- `/greetings`: show current settings.
- `/captcha on|off`, `/captcha type button|math|text`, `/captcha timeout 60`: verify new members before welcoming them. The bot needs permission to restrict members and delete messages. Text mode permits replies, consumes pending members' messages before normal commands, and accepts only replies to the current challenge. Button/math restrictions expire after 15 minutes if the bot restarts before completing verification.

Membership greetings use Telegram participant updates in supergroups. Changing a member's admin or mute status does not send a new greeting.
