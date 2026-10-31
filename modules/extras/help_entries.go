package extras

import modules "main/modules"

func init() {
	modules.Mods.AddModule("Misc", `<b>Misc</b>

<code>/tr &lt;lang&gt; &lt;text&gt;</code> — translate (or reply to a message), e.g. <code>/tr en hola</code>
<code>/detect &lt;text&gt;</code> — detect the language of a text
<code>/langs</code> — list language codes
<code>/autotr on|off</code> — auto-translate messages in this chat; <code>/autotr lang &lt;iso&gt;</code>, <code>/autotr min &lt;chars&gt;</code>
<code>/weather &lt;city&gt;</code> — current weather
<code>/nightmode on|off</code> — stop or allow members sending messages (needs Change Info)
<code>/tempnote &lt;duration&gt; &lt;name&gt; [content]</code> — note that deletes itself after e.g. <code>10m</code>, <code>1h</code> (or reply to a message)`)

	modules.Mods.AddModule("Crypto", `<b>Crypto</b>

<code>/price &lt;symbol&gt;</code> — price in USD/INR/EUR with 24h change and market cap
<code>/top</code> — top 10 coins by market cap
<code>/cryptochart &lt;symbol&gt;</code> — 7-day price chart
<code>/cryptonews</code> — latest headlines from CoinTelegraph and CoinDesk

Examples: <code>/price btc</code>, <code>/price solana</code>, <code>/cryptochart eth</code>`)

	modules.Mods.AddModule("GitHub", `<b>GitHub</b>

<code>/ghgraph &lt;username&gt;</code> — full insights card: power level, stats, contribution heatmap, languages, top repos and activity
<code>/gh &lt;username&gt;</code> — user profile
<code>/repo &lt;owner/repo&gt;</code> — repository details
<code>/ghcontrib &lt;username&gt;</code> — contributions in the last year, streaks and activity
<code>/ghissues &lt;owner/repo&gt;</code> — open issues
<code>/ghissue &lt;owner/repo&gt; &lt;number&gt;</code> — a single issue
<code>/ghrelease &lt;owner/repo&gt;</code> — latest release
<code>/ghemoji &lt;name&gt;</code> — GitHub emoji image

Example: <code>/repo xAmarnath/gogram</code>`)

	modules.Mods.AddModule("Stickers", `<b>Stickers</b>

<code>/kang [emoji]</code> — reply to a sticker, photo or video to add it to your pack
<code>/rmkang</code> — reply to a sticker to remove it from your pack
<code>/gif [emoji]</code> — reply to a GIF or short video to make a video sticker
<code>/mypacks</code> — list your packs
<code>/pack</code> — reply to a sticker to see its pack
<code>/renamepack &lt;short_name&gt; &lt;new title&gt;</code> — rename one of your packs
<code>/deletepack &lt;short_name&gt;</code> — delete one of your packs
<code>/stickerinfo</code> — reply to a sticker for its details
<code>/towebp</code> — reply to a static sticker to get it as an image file
<code>/tojpg</code> — reply to a webp image or static sticker to get a JPG
<code>/me &lt;action&gt;</code> — roleplay action message (also <code>/myself</code>)`)

	modules.Mods.AddModule("Social", `<b>Social Downloads</b>

<code>/insta &lt;url&gt;</code> — download Instagram posts and reels (also <code>/snap</code>)
<code>/tik &lt;url&gt;</code> — download TikTok videos
<code>/igmeta &lt;instagram url&gt;</code> — post details without downloading
<code>/tweet &lt;url&gt;</code> — show a tweet / X post
<code>/spotify &lt;track&gt;</code> — track details and preview
<code>/yt &lt;youtube link&gt;</code> — download a YouTube video (also <code>/youtube</code>)

Example: <code>/spotify imagine dragons believer</code>`)

	modules.Mods.AddModule("QR", `<b>QR Codes</b>

<code>/qr &lt;text&gt;</code> — make a QR code
<code>/qrcolor &lt;text&gt; &lt;fg_hex&gt; &lt;bg_hex&gt;</code> — coloured QR code
<code>/qrart &lt;text&gt;</code> — styled QR code (or reply to a message)
<code>/qrread</code> — reply to a QR image to decode it

Example: <code>/qrcolor hello ff0000 ffffff</code>`)

	modules.Mods.AddModule("Tools", `<b>Text &amp; Math Tools</b>

<code>/calc &lt;expression&gt;</code> — calculator: + - * / ^ ( )
<code>/eqsolve &lt;equation&gt;</code> — solve a linear equation, e.g. <code>2x+3=11</code>
<code>/unitconv &lt;n&gt; &lt;from&gt; &lt;to&gt;</code> — convert units, e.g. <code>10 km mi</code>, <code>100 f c</code>
<code>/markdown &lt;text&gt;</code> — render Markdown (or reply to a message)
<code>/jsonpretty</code>, <code>/jsonmin</code>, <code>/jsonvalid</code> — format, minify or validate JSON (text or reply)
<code>/yamlcvt</code> — convert simple YAML to JSON (text or reply)
<code>/musicinfo &lt;song&gt;</code> — song details from iTunes
<code>/avatar</code> — get a user's profile photo (reply or give a user)`)

	modules.Mods.AddModule("TamilMV", `<b>TamilMV</b>

<code>/tm</code> — latest releases (<code>/tm recent</code>, <code>/tm mal</code> for Malayalam, or <code>/tm &lt;title&gt;</code> to search)
<code>/tmalert &lt;title&gt; [interval]</code> — get notified when a title is posted
<code>/tmalerts</code> — list your alerts
<code>/tmalertoff &lt;id&gt;</code> — remove an alert
<code>/tmsettings</code> — manage alerts with buttons`)

	modules.Mods.AddModule("KissWatch", `<b>KissKH Watchlist</b> (bot admins)

<code>/kisswatch</code> — show the shared watchlist
<code>/kisswatch add &lt;drama&gt;</code> — watch a drama for new episodes
<code>/kisswatch remove &lt;ID&gt;</code> — stop watching
<code>/kisschannel &lt;channel ID or @username&gt;</code> — channel where new episodes are posted (the bot needs Post Messages)

New episodes are checked every 30 minutes.`)

	modules.Mods.AddModule("Mirror", `<b>Mirror</b> (transfer users)

<code>/mirror</code> — reply to a file, or give a t.me file link, to re-upload it
<code>/thumb</code> — reply to a photo or sticker to set your upload thumbnail`)
}
