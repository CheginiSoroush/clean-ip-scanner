#!/usr/bin/env bash
# Supervisor for the scan-service engine.
# bun's socket.io layer can hard-crash (silent segfault) when a websocket
# client disconnects abruptly (RST — tab close / killed test client).
# This loop restarts the engine within ~1s; queue + auto-scan state are
# file-persisted and restored on boot, so restarts are cheap and safe.
cd "$(dirname "$0")"
while true; do
  echo "[supervisor] starting engine at $(date '+%H:%M:%S')"
  bun index.ts
  code=$?
  echo "[supervisor] engine exited with code $code — restarting in 1s"
  sleep 1
done
