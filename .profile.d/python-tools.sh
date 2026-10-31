# The apt buildpack relocates Python; the yt-dlp package's /usr/bin/python3
# shebang does not point into the slug. Launch it with the bundled interpreter.
if [ -x "$HOME/.apt/usr/bin/python3" ]; then
  export PYTHONHOME="$HOME/.apt/usr"
  export PYTHONPATH="$HOME/.apt/usr/lib/python3/dist-packages${PYTHONPATH:+:$PYTHONPATH}"
  mkdir -p "$HOME/.local/bin"
  cat > "$HOME/.local/bin/yt-dlp" <<'YTDLP'
#!/bin/sh
exec "$HOME/.apt/usr/bin/python3" -m yt_dlp "$@"
YTDLP
  chmod u+x "$HOME/.local/bin/yt-dlp"
  export PATH="$HOME/.local/bin:$PATH"
fi
