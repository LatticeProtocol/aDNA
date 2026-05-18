#!/usr/bin/env bash
# pre-push-sanitize.sh — vault publish sanitization hook
#
# Source: .adna/how/standard/hooks/pre-push-sanitize.sh
# Installed by: skill_deploy (copies to .git/hooks/pre-push)
# Used by: skill_vault_publish (runs automatically on git push)
# Spec: how/campaigns/campaign_adna_v2_infrastructure/missions/artifacts/pre_push_hook_spec.md
#
# LAYER_CONTRACT_VERSION=4.0.1
#
# Exit codes:
#   0 = clean — push proceeds
#   1 = FAIL — sanitization violation; push aborted by git
#   2 = WARN — borderline finding; hook prompts operator confirmation
#
# Bypass (use sparingly):
#   git push --no-verify origin <branch>

set -euo pipefail

# ============================================================================
# Self-test mode (called by skill_deploy)
# ============================================================================
if [[ "${1:-}" == "--self-test" ]]; then
  fixtures_dir="$(dirname "$0")/../how/standard/hooks/test_fixtures"
  [[ -d "$fixtures_dir" ]] || fixtures_dir=".adna/how/standard/hooks/test_fixtures"
  if [[ ! -d "$fixtures_dir" ]]; then
    echo "WARN: self-test skipped — fixtures not found at $fixtures_dir"
    echo "WARN: install fixtures or run a real publish to verify."
    exit 0
  fi
  echo "INFO: self-test fixtures dir: $fixtures_dir"
  echo "INFO: self-test not yet implemented (deferred to M05 S2)"
  exit 0
fi

# ============================================================================
# Configuration
# ============================================================================
SANITIZE_MAX_BYTES="${SANITIZE_MAX_BYTES:-10485760}"  # 10 MiB
DENY_FILE_TEMPLATE=".adna/sanitize_deny.txt"
DENY_FILE_VAULT="sanitize_deny.txt"
NULL_SHA="0000000000000000000000000000000000000000"

# ============================================================================
# Read git push refs from stdin
# ============================================================================
declare -a ranges
while read -r local_ref local_sha remote_ref remote_sha; do
  # Skip delete operations
  [[ "$local_sha" == "$NULL_SHA" ]] && continue
  # New branch (no remote history) — compare against empty tree
  if [[ "$remote_sha" == "$NULL_SHA" ]]; then
    ranges+=("$local_sha")
  else
    ranges+=("$remote_sha..$local_sha")
  fi
done

# Empty push (nothing to check)
[[ ${#ranges[@]} -eq 0 ]] && exit 0

# ============================================================================
# Compute set of files about to be pushed
# ============================================================================
declare -a pushed_files
mapfile -t pushed_files < <(
  for range in "${ranges[@]}"; do
    if [[ "$range" == *..* ]]; then
      git diff --name-only "$range" 2>/dev/null
    else
      # New branch — list all files in the pushed commit
      git ls-tree -r --name-only "$range" 2>/dev/null
    fi
  done | sort -u
)

[[ ${#pushed_files[@]} -eq 0 ]] && exit 0

# ============================================================================
# Findings accumulators
# ============================================================================
fail_findings=()
warn_findings=()

# ============================================================================
# R1: Local/private directory leakage (FAIL)
# ============================================================================
for f in "${pushed_files[@]}"; do
  case "$f" in
    what/local/*|how/local/*|who/operators/*|deploy/*|\
    .publish-clone/*|.publish-clone.bak/*|private/*)
      fail_findings+=("R1: $f (private path leakage)")
      ;;
  esac
done

# ============================================================================
# R2: Secret-pattern matches (FAIL; redact when reporting)
# ============================================================================
# Patterns: API keys, GH tokens, OpenAI/Anthropic keys, private keys, AWS, latlab
declare -a secret_patterns=(
  '([Aa][Pp][Ii]|[Ss][Ee][Cc][Rr][Ee][Tt]|[Aa][Cc][Cc][Ee][Ss][Ss])[_-]?([Kk][Ee][Yy]|[Tt][Oo][Kk][Ee][Nn])[[:space:]]*[:=][[:space:]]*[\x27\x22]?[A-Za-z0-9_\-]{20,}'
  '([Gg][Ii][Tt][Hh][Uu][Bb]|[Gg][Hh])[_-]?[Tt][Oo][Kk][Ee][Nn][[:space:]]*[:=][[:space:]]*[\x27\x22]?gh[psoru]_[A-Za-z0-9]{36,}'
  '[Oo][Pp][Ee][Nn][Aa][Ii][_-]?[Aa][Pp][Ii][_-]?[Kk][Ee][Yy][[:space:]]*[:=][[:space:]]*[\x27\x22]?sk-[A-Za-z0-9]{40,}'
  '[Aa][Nn][Tt][Hh][Rr][Oo][Pp][Ii][Cc][_-]?[Aa][Pp][Ii][_-]?[Kk][Ee][Yy][[:space:]]*[:=][[:space:]]*[\x27\x22]?sk-ant-[A-Za-z0-9_\-]{40,}'
  '-----BEGIN (RSA |EC |OPENSSH |DSA |)PRIVATE KEY-----'
  '[Aa][Ww][Ss]_[Ss][Ee][Cc][Rr][Ee][Tt]_[Aa][Cc][Cc][Ee][Ss][Ss]_[Kk][Ee][Yy][[:space:]]*[:=][[:space:]]*[\x27\x22]?[A-Za-z0-9/+=]{40}'
  '[Ll][Aa][Tt][Ll][Aa][Bb][_-]?[Tt][Oo][Kk][Ee][Nn][[:space:]]*[:=][[:space:]]*[\x27\x22]?[A-Za-z0-9_\-]{20,}'
)

for f in "${pushed_files[@]}"; do
  # Skip non-existing files (deleted in the push)
  [[ -f "$f" ]] || continue
  # Skip binary files
  if file --mime "$f" 2>/dev/null | grep -q 'charset=binary'; then
    continue
  fi
  # Skip if line contains pragma: allowlist secret
  for pattern in "${secret_patterns[@]}"; do
    while IFS=: read -r lineno content; do
      [[ -z "$lineno" ]] && continue
      # Honor pragma: allowlist secret comment
      if echo "$content" | grep -qE 'pragma:[[:space:]]*allowlist[[:space:]]+secret'; then
        continue
      fi
      # Redact: show first 4 chars of any captured group + "***"
      redacted=$(echo "$content" | grep -oE '[A-Za-z0-9_\-]{20,}' | head -1 | cut -c1-4)
      fail_findings+=("R2: ${f}:${lineno} (secret pattern match; redacted='${redacted}***')")
    done < <(grep -nE "$pattern" "$f" 2>/dev/null || true)
  done
done

# ============================================================================
# R3: Filename patterns (FAIL)
# ============================================================================
for f in "${pushed_files[@]}"; do
  case "$(basename "$f")" in
    .env|.env.*|id_rsa|id_ed25519|id_ecdsa|id_dsa)
      fail_findings+=("R3: $f (filename pattern: credential file)")
      ;;
    secrets|secrets.yaml|secrets.yml|secrets.json|secrets.toml|secrets.ini)
      fail_findings+=("R3: $f (filename pattern: secrets file)")
      ;;
  esac
  # .pem files: check content for private-key headers (handled by R2 too; cheap front-line check)
  if [[ "$f" == *.pem ]] && [[ -f "$f" ]]; then
    if grep -q "BEGIN .*PRIVATE KEY" "$f" 2>/dev/null; then
      fail_findings+=("R3: $f (filename .pem with private-key content)")
    fi
  fi
  # .netrc / .npmrc with auth tokens
  if [[ "$(basename "$f")" == ".netrc" || "$(basename "$f")" == ".npmrc" ]] && [[ -f "$f" ]]; then
    if grep -qE "(_authToken|password)[[:space:]]*=" "$f" 2>/dev/null; then
      fail_findings+=("R3: $f (filename .netrc/.npmrc with auth tokens)")
    fi
  fi
done

# ============================================================================
# R4: Large binary files (WARN)
# ============================================================================
for f in "${pushed_files[@]}"; do
  [[ -f "$f" ]] || continue
  size=$(stat -f%z "$f" 2>/dev/null || stat -c%s "$f" 2>/dev/null || echo 0)
  if [[ "$size" -gt "$SANITIZE_MAX_BYTES" ]]; then
    warn_findings+=("R4: $f (size $size bytes > threshold $SANITIZE_MAX_BYTES)")
  fi
done

# ============================================================================
# R5/R6: Frontmatter confidential|private (FAIL) / status: draft (WARN)
# ============================================================================
for f in "${pushed_files[@]}"; do
  [[ "$f" == *.md ]] || continue
  [[ -f "$f" ]] || continue
  # Extract first --- block (lines between first two --- markers)
  fm=$(awk '/^---$/{c++; if(c==1) next; if(c==2) exit} c==1' "$f" 2>/dev/null)
  [[ -z "$fm" ]] && continue
  # R5: confidential|private = true
  if echo "$fm" | grep -qE '^(confidential|private)[[:space:]]*:[[:space:]]*true'; then
    fail_findings+=("R5: $f (frontmatter flagged confidential|private: true)")
  fi
  # R6: status: draft
  if echo "$fm" | grep -qE '^status[[:space:]]*:[[:space:]]*draft'; then
    warn_findings+=("R6: $f (frontmatter status: draft)")
  fi
done

# ============================================================================
# R7: Operator-defined deny list (FAIL)
# ============================================================================
for deny_file in "$DENY_FILE_TEMPLATE" "$DENY_FILE_VAULT"; do
  [[ -f "$deny_file" ]] || continue
  while IFS= read -r line; do
    # Skip blank lines and comments
    [[ -z "$line" || "$line" =~ ^[[:space:]]*# ]] && continue
    if [[ "$line" =~ ^re: ]]; then
      pattern="${line#re:}"
      for f in "${pushed_files[@]}"; do
        if [[ "$f" =~ $pattern ]]; then
          fail_findings+=("R7: $f (deny regex: $pattern)")
        fi
      done
    else
      for f in "${pushed_files[@]}"; do
        if [[ "$f" == "$line"* ]]; then
          fail_findings+=("R7: $f (deny prefix: $line)")
        fi
      done
    fi
  done < "$deny_file"
done

# ============================================================================
# Decision
# ============================================================================
if [[ ${#fail_findings[@]} -gt 0 ]]; then
  echo ""
  echo "❌ pre-push-sanitize: FAIL — push aborted"
  printf '  %s\n' "${fail_findings[@]}"
  echo ""
  echo "Remediate the findings above (or add 'pragma: allowlist secret' on false-positive secret lines), recommit, then retry."
  echo "Emergency bypass (use sparingly): git push --no-verify origin <branch>"
  exit 1
fi

if [[ ${#warn_findings[@]} -gt 0 ]]; then
  echo ""
  echo "⚠ pre-push-sanitize: WARN — borderline findings"
  printf '  %s\n' "${warn_findings[@]}"
  echo ""
  # Read prompt from tty (stdin is git's ref list)
  if [[ -t 0 ]] || [[ ! -e /dev/tty ]]; then
    echo "INFO: no tty available; treating WARN as FAIL (no operator to confirm)."
    exit 1
  fi
  read -p "Continue with push? [y/N] " yn < /dev/tty
  if [[ "$yn" =~ ^[Yy]$ ]]; then
    echo "INFO: operator confirmed; proceeding with push."
    exit 0
  else
    echo "INFO: push aborted by operator."
    exit 1
  fi
fi

echo "✓ pre-push-sanitize: clean (${#pushed_files[@]} files checked)"
exit 0
