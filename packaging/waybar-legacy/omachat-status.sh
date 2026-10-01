#!/bin/sh
set -eu
if output=$(/usr/bin/timeout 1s /usr/bin/omachat-ctl status --json 2>/dev/null); then
  state=$(printf '%s\n' "$output" | /usr/bin/jq -r '.hosted.state')
  if [ "$state" = connected ]; then
    printf '{"text":"OC online","class":"online"}\n'
  else
    printf '{"text":"OC offline","class":"offline"}\n'
  fi
else
  printf '{"text":"OC —","class":"offline"}\n'
fi
