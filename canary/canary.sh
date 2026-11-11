#!/bin/sh
# KeyTap canary — the whole chain once, with the real things: this computer, your iPhone, your YubiKey.
#
#   canary/canary.sh [options] [step ...]
#
# Steps, in this order (default: all that apply):
#   pair      pair the iPhone with this computer (only with --pair, or when no phone is paired yet)
#   dry-run   age-plugin-yubikey-phone test: PIN + tap + key agreement, nothing decrypted
#   decrypt   age decrypts a throwaway file — approve on the phone
#   decline   the same again — DECLINE on the phone; the decryption must fail
#   sops      sops decrypts a throwaway file (skipped without sops)
#   ssh       an SSH login with a FIDO2 key on the YubiKey, to a throwaway sshd on 127.0.0.1
#             (skipped without a key file or without the security key provider)
#
# Options:
#   --pair            pair first, even if a phone is already paired
#   --host IP         address the iPhone reaches this computer at (pair; default: this computer's LAN address)
#   --port N          port for pair (default: the bridge's)
#   --name NAME       how the phone shows this computer (pair)
#   --key LABEL       which YubiKey the dry run asks for (default: the last one used)
#   --ssh-key FILE    FIDO2 key handle file (id_ed25519_sk); repeat for several. Default: $KEYTAP_SSH_KEY,
#                     the `ssh` entries of keys.conf, ~/.ssh/id_ed25519_sk
#   --no-copy         do not put the pairing link on the clipboard
#   --hide-serials    leave the YubiKeys' serial numbers out of what is printed here (for a recording)
#   --yes             do not wait for Return before each step
#
# Nothing real is touched: the files are made here, in a temp directory, encrypted to the recipients named
# in your identity file's comments, and deleted at the end; sshd is a private one on 127.0.0.1 that accepts
# only your key and is stopped at the end. No YubiKey slot is written. The bridge is the installed one
# (KEYTAP_BRIDGE overrides), asked directly — whatever else is named age-plugin-yubikey on your PATH.
set -eu

bridge=${KEYTAP_BRIDGE:-age-plugin-yubikey-phone}
identities=${KEYTAP_IDENTITIES:-$HOME/.secure/age/yubikeys.agekey}
keysconf=${KEYTAP_KEYS:-${KEYTAP_DIR:-$HOME/.secure/keytap}/keys.conf}
sshport=${KEYTAP_CANARY_SSH_PORT:-12222}
pair=0; host=""; port=""; name=""; key=""; copy=1; yes=0; hide=0; steps=""; sshkeys=""
nl='
'
while [ $# -gt 0 ]; do
  case "$1" in
    --pair) pair=1; shift ;;
    --host) host=$2; shift 2 ;;
    --port) port=$2; shift 2 ;;
    --name) name=$2; shift 2 ;;
    --key) key=$2; shift 2 ;;
    --ssh-key) sshkeys="$sshkeys$2$nl"; shift 2 ;;
    --no-copy) copy=0; shift ;;
    --hide-serials) hide=1; shift ;;
    --yes) yes=1; shift ;;
    -h|--help) sed -n '2,/^set -eu/p' "$0" | sed '$d; s/^# \{0,1\}//'; exit 0 ;;
    pair|dry-run|decrypt|decline|sops|ssh) steps="$steps $1"; shift ;;
    *) echo "canary: unknown argument $1 (see --help)" >&2; exit 2 ;;
  esac
done

say() { printf '%s\n' "$*"; }
die() { printf '\n✗ canary failed: %s\n' "$*" >&2; exit 1; }
n=0; passed=""; skipped=""
step() { # step <name> <title> <what to do on the phone>
  n=$((n + 1)); current=$1
  printf '\n── %d · %s\n   %s\n' "$n" "$2" "$3"
  if [ "$yes" = 0 ]; then printf '   Press Return to start … '; read -r _; fi
}
serials() { # the bridge's lines, without serial numbers when asked
  if [ "$hide" = 1 ]; then sed -E 's/ \(YubiKey [0-9]+, slot [^)]*\)//; s/^( +[^ ]+) +[0-9]+$/\1/'; else cat; fi
}
ok() { passed="$passed $current"; say "   ✓ $*"; }
skip() { skipped="$skipped $1"; printf '\n── skipped: %s — %s\n' "$1" "$2"; }

command -v "$bridge" >/dev/null 2>&1 || die "the KeyTap bridge ($bridge) is not installed — https://keytap.me/install"
bridge=$(command -v "$bridge")
work=$(mktemp -d "${TMPDIR:-/tmp}/keytap-canary.XXXXXX")
cleanup() {
  [ -f "$work/sshd.pid" ] && kill "$(cat "$work/sshd.pid")" 2>/dev/null || true
  [ -n "${pairpid:-}" ] && kill "$pairpid" 2>/dev/null || true
  rm -rf "$work" || true
}
trap cleanup EXIT
trap 'exit 130' INT TERM

# age and sops start the plugin by name: in here, that name is the bridge and nothing else.
mkdir -p "$work/path"
ln -s "$bridge" "$work/path/age-plugin-yubikey"
PATH="$work/path:$PATH"; export PATH

paired() { ! "$bridge" devices 2>/dev/null | grep -q '^no paired devices'; }
if [ -z "$steps" ]; then
  steps="dry-run decrypt decline sops ssh"
  if [ "$pair" = 1 ] || ! paired; then steps="pair $steps"; fi
fi
wants() { case " $steps " in *" $1 "*) return 0 ;; *) return 1 ;; esac; }

say "KeyTap canary — $("$bridge" version 2>/dev/null || echo "$bridge")"
say "Have ready: the iPhone with KeyTap open, and your YubiKey."

recipients() { # every age recipient the identity file's comments name, comma-separated
  [ -f "$identities" ] || die "no identity file at $identities (age-plugin-yubikey --identity > that file; KEYTAP_IDENTITIES overrides)"
  r=$(sed -n 's/^#.*Recipient: *\(age1yubikey1[0-9a-z]*\).*/\1/p' "$identities" | paste -sd, -)
  [ -n "$r" ] || die "$identities names no recipient (it needs age-plugin-yubikey's comments above each identity)"
  say "$r"
}
encrypt() { # encrypt <recipients> <file in $work>: age, to every recipient
  set -- "$2" $(say "$1" | tr ',' ' ')
  f=$1; shift
  for r in "$@"; do set -- "$@" -r "$r"; shift; done
  age "$@" -o "$work/$f.age" "$work/$f"
}
throwaway() { say "KeyTap canary $(date -u +%Y-%m-%dT%H:%M:%SZ) $(od -An -N8 -tx1 /dev/urandom | tr -d ' \n')"; }

# ── pair ────────────────────────────────────────────────────────────────────────────────────────────
if wants pair; then
  if [ -z "$host" ]; then
    for i in en0 en1; do host=$(ipconfig getifaddr "$i" 2>/dev/null || true); [ -n "$host" ] && break; done
    [ -n "$host" ] || host=$(hostname -I 2>/dev/null | awk '{print $1}' || true)
    [ -n "$host" ] || die "pass --host: the address the iPhone reaches this computer at"
  fi
  step pair "Pair the iPhone with this computer ($host)" \
    "On the iPhone: scan the code below with the camera (or paste the link in KeyTap ▸ Set Up ▸ Pair), then tap Pair."
  set -- pair --host "$host"
  [ -n "$port" ] && set -- "$@" --port "$port"
  [ -n "$name" ] && set -- "$@" --name "$name"
  "$bridge" "$@" > "$work/pair.out" 2>&1 &
  pairpid=$!
  link=""
  for _ in $(seq 50); do
    link=$(grep -o 'keytap://pair[^ ]*' "$work/pair.out" || true); [ -n "$link" ] && break
    kill -0 "$pairpid" 2>/dev/null || break
    sleep 0.1
  done
  [ -n "$link" ] || { cat "$work/pair.out" >&2; die "the bridge printed no pairing link"; }
  say ""; say "   $link"; say ""
  # the link as a QR code: the bridge draws it (v0.5.2 or later), else qrencode where there is one
  if "$bridge" qr "$link" > "$work/qr.out" 2>/dev/null || { command -v qrencode >/dev/null 2>&1 && qrencode -t ANSIUTF8 -m 2 "$link" > "$work/qr.out"; }; then
    sed 's/^/   /' "$work/qr.out"; say ""
    say "   Scan this with the iPhone's camera and tap \"Open in KeyTap\" — or paste the link above."
  fi
  if [ "$copy" = 1 ]; then
    for c in pbcopy wl-copy "xclip -selection clipboard"; do
      if command -v "${c%% *}" >/dev/null 2>&1 && printf '%s' "$link" | $c 2>/dev/null; then
        say "   The link is on this computer's clipboard (with Universal Clipboard: on the iPhone's too)."; break
      fi
    done
  fi
  say "   Waiting for the iPhone (one-time link, 10 minutes) …"
  wait "$pairpid" || { pairpid=""; cat "$work/pair.out" >&2; die "pairing did not finish"; }
  pairpid=""
  sed -n '/^Paired /,$p' "$work/pair.out" | grep -v '^Next:' | serials | sed 's/^/   /'
  ok "paired"
fi
paired || die "no phone is paired with this computer — run with --pair"

# ── dry run ─────────────────────────────────────────────────────────────────────────────────────────
if wants dry-run; then
  step dry-run "Dry run through the phone (nothing is decrypted)" \
    "On the iPhone: the request appears — compare the code, enter the YubiKey's PIN, hold the key to the top of the iPhone."
  set -- test --note "KeyTap canary: dry run. PIN, tap and key agreement on the YubiKey — nothing is decrypted."
  [ -n "$key" ] && set -- "$@" --key "$key"
  "$bridge" "$@" 2>&1 | tee "$work/test.out" | serials | sed 's/^/   /' || true
  grep -q 'Dry run passed' "$work/test.out" || die "the dry run did not pass"
  ok "dry run passed"
fi

# ── age: decrypt, then decline ──────────────────────────────────────────────────────────────────────
if wants decrypt; then
  command -v age >/dev/null 2>&1 || die "age is not installed"
  rcp=$(recipients)
  throwaway > "$work/canary.txt"
  encrypt "$rcp" canary.txt
  step decrypt "age decrypts a throwaway file" \
    "On the iPhone: approve — PIN, then hold the YubiKey to the iPhone. Only the 16-byte file key comes back."
  say "   \$ age -d canary.txt.age"
  (cd "$work" && KEYTAP_NOTE="KeyTap canary: decrypting a throwaway file made a moment ago. Approve it." \
    age -d -i "$identities" -o "$work/canary.out" canary.txt.age </dev/null) 2>&1 | sed 's/^/   /' \
    || true
  [ -f "$work/canary.out" ] && cmp -s "$work/canary.txt" "$work/canary.out" || die "age did not decrypt the file"
  say "   $(cat "$work/canary.out")"
  ok "decrypted, identical to the original"
fi

if wants decline; then
  command -v age >/dev/null 2>&1 || die "age is not installed"
  rcp=$(recipients)
  throwaway > "$work/decline.txt"
  encrypt "$rcp" decline.txt
  step decline "A request you refuse" \
    "On the iPhone: tap DECLINE. The computer must get nothing."
  say "   \$ age -d decline.txt.age"
  if (cd "$work" && KEYTAP_NOTE="KeyTap canary: DECLINE this one — the decryption has to fail." \
       age -d -i "$identities" -o "$work/decline.out" decline.txt.age </dev/null) 2>"$work/decline.err"; then
    die "the file was decrypted although the request should have been declined"
  fi
  sed 's/^/   /' "$work/decline.err"
  grep -q -i 'declined' "$work/decline.err" || die "the decryption failed, but not because the phone declined"
  [ ! -s "$work/decline.out" ] || die "plaintext was written after a decline"
  ok "declined on the phone → nothing decrypted"
fi

# ── sops ────────────────────────────────────────────────────────────────────────────────────────────
if wants sops; then
  if ! command -v sops >/dev/null 2>&1; then skip sops "sops is not installed"
  else
    rcp=$(recipients)
    printf 'canary: %s\n' "$(throwaway)" > "$work/canary.yaml"
    (cd "$work" && sops -e --age "$rcp" canary.yaml > canary.enc.yaml)
    step sops "sops decrypts a throwaway file" \
      "On the iPhone: approve — PIN and tap. Any of the file's YubiKeys answers, with one tap."
    say "   \$ sops -d canary.enc.yaml"
    (cd "$work" && KEYTAP_NOTE="KeyTap canary: sops decrypts a throwaway YAML file. Approve it." \
      SOPS_AGE_KEY_FILE="$identities" sops -d canary.enc.yaml </dev/null > "$work/canary.out.yaml") 2>&1 | sed 's/^/   /' || true
    cmp -s "$work/canary.yaml" "$work/canary.out.yaml" || die "sops did not decrypt the file"
    sed 's/^/   /' "$work/canary.out.yaml"
    ok "decrypted, identical to the original"
  fi
fi

# ── ssh ─────────────────────────────────────────────────────────────────────────────────────────────
ssh_step() {
  if [ -z "$sshkeys" ] && [ -n "${KEYTAP_SSH_KEY:-}" ]; then sshkeys="$KEYTAP_SSH_KEY$nl"; fi
  if [ -z "$sshkeys" ] && [ -f "$keysconf" ]; then
    sshkeys=$(sed 's/#.*//' "$keysconf" | awk '{ for (i = 3; i < NF; i += 2) if ($i == "ssh") { p = $(i + 1); sub(/\.pub$/, "", p); print p } }')
    [ -n "$sshkeys" ] && sshkeys="$sshkeys$nl"
  fi
  if [ -z "$sshkeys" ] && [ -f "$HOME/.ssh/id_ed25519_sk" ]; then sshkeys="$HOME/.ssh/id_ed25519_sk$nl"; fi
  [ -n "$sshkeys" ] || { skip ssh "no FIDO2 key file (--ssh-key ~/.ssh/id_ed25519_sk; made with ssh-keygen -t ed25519-sk)"; return 0; }

  oldifs=$IFS; IFS=$nl
  set --
  for k in $sshkeys; do
    case "$k" in "~/"*) k="$HOME/${k#\~/}" ;; esac
    [ -f "$k" ] && [ -f "$k.pub" ] || { IFS=$oldifs; skip ssh "key file $k (and $k.pub) not found"; return 0; }
    set -- "$@" "$k"
  done
  IFS=$oldifs
  if ! "$bridge" ssh-opts "$@" > "$work/ssh.opts" 2>"$work/ssh.opts.err"; then
    skip ssh "$(sed 's/^keytap: //' "$work/ssh.opts.err" | head -1)"; return 0
  fi

  # Homebrew's OpenSSH where there is one (macOS: the one the provider is tested with), else the system's
  prefix=$(brew --prefix openssh 2>/dev/null || true)
  if [ -n "$prefix" ] && [ -x "$prefix/bin/ssh" ] && [ -x "$prefix/sbin/sshd" ]; then
    ssh="$prefix/bin/ssh"; sshd="$prefix/sbin/sshd"; keygen="$prefix/bin/ssh-keygen"
  else
    ssh=$(command -v ssh || true); keygen=$(command -v ssh-keygen || true)
    sshd=$(command -v sshd || true); [ -n "$sshd" ] || sshd=/usr/sbin/sshd
  fi
  [ -x "$ssh" ] && [ -x "$sshd" ] && [ -x "$keygen" ] || { skip ssh "OpenSSH (ssh, sshd, ssh-keygen) not found"; return 0; }

  "$keygen" -q -t ed25519 -N '' -f "$work/host_key"
  for k in "$@"; do cat "$k.pub"; done > "$work/authorized_keys"
  chmod 600 "$work/authorized_keys"
  cat > "$work/sshd_config" <<EOF
Port $sshport
ListenAddress 127.0.0.1
HostKey $work/host_key
PidFile $work/sshd.pid
AuthorizedKeysFile $work/authorized_keys
PubkeyAuthentication yes
PasswordAuthentication no
KbdInteractiveAuthentication no
UsePAM no
StrictModes no
EOF
  "$sshd" -f "$work/sshd_config" -E "$work/sshd.log" || { skip ssh "could not start a throwaway sshd on 127.0.0.1:$sshport"; return 0; }
  for _ in $(seq 50); do [ -f "$work/sshd.pid" ] && break; sleep 0.1; done
  [ -f "$work/sshd.pid" ] || { skip ssh "the throwaway sshd did not start (port $sshport in use? KEYTAP_CANARY_SSH_PORT)"; return 0; }

  step ssh "SSH login with the FIDO2 key on the YubiKey" \
    "On the iPhone: approve — the YubiKey's FIDO2 PIN, then hold the key to the iPhone. Only the signature comes back."
  me=$(id -un)
  say "   \$ ssh $me@127.0.0.1    (a throwaway sshd on this computer, port $sshport)"
  # keys made with verify-required make ssh ask for a PIN first: answered empty, the PIN is entered on the phone
  printf '#!/bin/sh\ncase "$1" in *PIN*) echo ;; esac\n' > "$work/askpass"; chmod 755 "$work/askpass"
  IFS=$nl
  # shellcheck disable=SC2046
  set -- $(cat "$work/ssh.opts")
  IFS=$oldifs
  out=$(KEYTAP_NOTE="KeyTap canary: SSH login to a throwaway sshd on this computer. Approve it." \
    SSH_ASKPASS="$work/askpass" SSH_ASKPASS_REQUIRE=force \
    "$ssh" -F /dev/null -p "$sshport" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o BatchMode=no \
    "$@" "$me@127.0.0.1" 'echo keytap-canary-logged-in' </dev/null 2>"$work/ssh.err") || {
      sed 's/^/   /' "$work/ssh.err" >&2; die "the SSH login failed"; }
  [ "$out" = keytap-canary-logged-in ] || die "unexpected answer from the SSH login: $out"
  grep 'Accepted publickey' "$work/sshd.log" | sed 's/^.*Accepted/   sshd: Accepted/' | head -1
  ok "logged in as $me"
}
if wants ssh; then ssh_step; fi

printf '\n'
[ -n "$passed" ] || die "no step ran"
say "✓ KeyTap canary passed:$passed"
[ -z "$skipped" ] || say "  skipped:$skipped"
