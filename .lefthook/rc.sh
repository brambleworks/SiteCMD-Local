#!/bin/sh

if [ "${0##*/}" = pre-push ]; then
  set +x
  # Preserve Git's arguments before Lefthook can interpolate them into a command.
  export SITECMD_PUSH_REMOTE="$1" SITECMD_PUSH_URL="$2"
  set --
fi
