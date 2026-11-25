#!/bin/sh

unset SITECMD_PUSH_REMOTE SITECMD_PUSH_URL
# Keep the final newline so the comparison preserves every byte of the URL.
configured_url=$(git remote get-url --push -- "$1" 2>/dev/null && printf '.')
case $? in
  0)
    if [ "$configured_url" != "$(printf '%s\n.' "$2")" ]; then
      printf '%s\n' 'Git pre-push URL does not match the configured push URL. Run pnpm exec lefthook install to refresh Git hooks.' >&2
      exit 2
    fi
    ;;
  2) ;;
  *)
    printf '%s\n' 'Could not read the configured Git push URL.' >&2
    exit 2
    ;;
esac
exec node tools/scripts/check-publication-history.mjs --pre-push "$@"
