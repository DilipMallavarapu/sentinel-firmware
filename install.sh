#!/usr/bin/env bash
# install.sh -- move Sentinel files from a download directory into the tree.
#
#   ./install.sh                 # pulls from ~/Downloads
#   ./install.sh ~/some/dir      # or anywhere else
#   ./install.sh --dry-run
#
# Handles what browsers actually do to filenames: capitalised duplicates
# (Main.go), collision suffixes (secrets(1).py, secrets-2.py), and the NTFS
# alternate data stream WSL surfaces as name:Zone.Identifier. When several
# copies of the same file exist it takes the newest by mtime.
#
# Run from the repo root. Everything is copied, never moved, so a bad guess
# on your part costs nothing and the downloads stay put.

set -uo pipefail

SRC="${1:-$HOME/Downloads}"
DRY=0
FORCE=0
for a in "$@"; do
  case "$a" in
    --dry-run) DRY=1 ;;
    --force)   FORCE=1 ;;
  esac
done
case "${1:-}" in --dry-run|--force) SRC="$HOME/Downloads" ;; esac

if [ ! -d sentinel ] || [ ! -d go ]; then
  echo "error: run this from the repo root (no sentinel/ or go/ here)" >&2
  exit 1
fi
if [ ! -d "$SRC" ]; then
  echo "error: $SRC is not a directory" >&2
  exit 1
fi

# canonical name -> destination directory
route() {
  case "$1" in
    secrets.py|services.py|hardening.py)  echo sentinel/firmware/analyzers ;;
    emulate.py|pipeline.py|models.py|unpack.py) echo sentinel/firmware ;;
    contracts.py|verifiers.py|checkpoint.py|goworker.py) echo sentinel/core ;;
    cli.py)             echo sentinel ;;
    main.go)            echo go/elfscan ;;
    firmware_run.html)  echo ui ;;
    schema.md)          echo sentinel/templates ;;
    architecture.md|smoke_test.py|scan_rootfs.py|bootstrap.sh|\
    extend_fixture.sh|apply_fixes.py|dockerfile|makefile|\
    docker-compose.yml|requirements.txt|install.sh) echo . ;;
    gitignore.txt)      echo .gitignore ;;   # special: renamed on arrival
    *)                  echo "" ;;
  esac
}

# Strip browser collision suffixes and lowercase, so "Secrets (1).py" and
# "secrets-2.py" both resolve to "secrets.py".
canon() {
  local b="${1##*/}"
  b="${b%:Zone.Identifier}"
  b="$(printf '%s' "$b" | sed -E 's/[ _-]*\(?[0-9]+\)?(\.[A-Za-z0-9]+)$/\1/')"
  printf '%s' "$b" | tr '[:upper:]' '[:lower:]'
}

declare -A best_path best_time
while IFS= read -r -d '' f; do
  case "$f" in *:Zone.Identifier) continue ;; esac
  c="$(canon "$f")"
  [ -n "$(route "$c")" ] || continue
  t=$(stat -c %Y "$f" 2>/dev/null || echo 0)
  if [ -z "${best_time[$c]:-}" ] || [ "$t" -gt "${best_time[$c]}" ]; then
    best_path[$c]="$f"; best_time[$c]="$t"
  fi
done < <(find "$SRC" -maxdepth 1 -type f -print0)

if [ "${#best_path[@]}" -eq 0 ]; then
  echo "nothing recognised in $SRC"
  exit 0
fi

placed=0
skipped=0
for c in $(printf '%s\n' "${!best_path[@]}" | sort); do
  src="${best_path[$c]}"
  dest="$(route "$c")"

  if [ "$dest" = ".gitignore" ]; then
    target=".gitignore"
  else
    # Preserve the canonical lowercase name; the tree is case-sensitive and
    # `from .analyzers.hardening import ...` will not find Hardening.py.
    target="$dest/$c"
    mkdir -p "$dest"
  fi

  if [ -f "$target" ] && cmp -s "$src" "$target"; then
    printf '  same      %s\n' "$target"
    continue
  fi

  # Never let a stale download clobber a newer file in the tree. An in-place
  # patch produces a tree file newer than the download it came from, and
  # copying over it silently reverts the fix -- which is exactly what
  # happened, twice, before this guard existed.
  if [ -f "$target" ] && [ "$target" -nt "$src" ] && [ "$FORCE" -eq 0 ]; then
    printf '  SKIP      %-44s tree copy is newer (--force to override)\n' "$target"
    skipped=$((skipped + 1))
    continue
  fi
  verb="update"; [ -f "$target" ] || verb="new   "
  printf '  %s    %-44s <- %s\n' "$verb" "$target" "${src##*/}"
  # cp without -p on purpose: the tree copy must read as NEWER than the
  # download, or the staleness guard above can never fire.
  [ "$DRY" -eq 1 ] || { cp "$src" "$target"
                        case "$c" in *.sh) chmod +x "$target" ;; esac; }
  placed=$((placed + 1))
done

[ "$DRY" -eq 1 ] && { echo "(dry run, nothing written)"; exit 0; }
find . -name '*:Zone.Identifier' -delete 2>/dev/null
find . -name __pycache__ -type d -exec rm -rf {} + 2>/dev/null

echo
echo "$placed file(s) placed, $skipped skipped as older. verify:"
echo "  go build -o bin/elfscan ./go/elfscan && python3 smoke_test.py | tail -2"
