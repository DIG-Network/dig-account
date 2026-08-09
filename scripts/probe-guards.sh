#!/usr/bin/env bash
# Delete-probe every custody guard: neutralize it, run the suite, restore. RED = a test caught it, so
# the guard is load-bearing. GREEN = no test can tell the guard apart from its absence, which line
# coverage cannot see: this crate shipped 96% coverage over two guards that were mutually masking.
#
# Run after changing anything in the custody path, and record the per-guard verdict in the PR body.
# Every mutation is applied to ONE guard at a time and reverted immediately -- including on Ctrl-C, via
# the EXIT trap -- so an interrupted run leaves the tree clean.
#
# EXIT STATUS IS THE RESULT. A probe that could only ever print is not evidence: an earlier version ran
# from the wrong directory, so every pattern missed, every guard went unprobed, and it exited 0 while
# reporting nothing. Any PATTERN-MISS, any INCONCLUSIVE, and any GREEN-VACUOUS guard now fails the run.
set -uo pipefail

# The repo root, not this script's directory -- every path below is relative to the crate.
cd "$(dirname "$0")/.."

BACKUP=$(mktemp)
readonly BACKUP
CURRENT=""
restore() { [ -n "$CURRENT" ] && cp "$BACKUP" "$CURRENT"; CURRENT=""; }
trap 'restore; rm -f "$BACKUP"' EXIT

misses=0
vacuous=0
inconclusive=0

# probe <name> <file> <guard-text> <neutralized-text> [expect]
#
# `expect` defaults to `red` -- the guard must be load-bearing. The one other accepted value is
# `vacuous:<reason>`, for a guard that is REACHABLE but whose reaching input cannot be built yet. Such
# an exemption is self-expiring: if the guard goes RED the exemption is stale and the run FAILS, so the
# exemption cannot outlive the blocker that justified it.
probe() {
  local name="$1" file="$2" from="$3" to="$4" expect="${5:-red}"

  # Back up BEFORE claiming the file, and only claim it if the backup succeeded. `BACKUP` is one
  # shared temp file, so a `cp` that fails here leaves the PREVIOUS probe's contents in it -- and the
  # restore would then write that unrelated source into `$file`. A probe that cannot read its target
  # must abort the run, never reach the restore path.
  if ! cp "$file" "$BACKUP" 2>/dev/null; then
    echo "$name :: PATTERN-MISS (cannot read $file; the probe names a file that is not there)"
    misses=$((misses + 1))
    return
  fi
  CURRENT="$file"

  if ! python3 - "$file" "$from" "$to" <<'PY'
import io, sys
path, guard, neutralized = sys.argv[1], sys.argv[2], sys.argv[3]
source = io.open(path, encoding='utf-8').read()
if guard not in source:
    sys.exit(3)
io.open(path, 'w', encoding='utf-8', newline='').write(source.replace(guard, neutralized, 1))
PY
  then
    # The guard text no longer appears, so this probe tested NOTHING. Almost always a stale pattern
    # after a refactor -- which is exactly when a rotted probe is most dangerous.
    echo "$name :: PATTERN-MISS (the guard text is not in $file; the probe is stale)"
    misses=$((misses + 1))
    restore
    return
  fi

  local out
  out=$(cargo test --all-features 2>&1)
  local failed
  failed=$(echo "$out" | sed -n '/^failures:$/,$p' | grep -oE "^    [a-z_][a-z_0-9:]*$" | tr -d ' ' | sort -u | tr '\n' ' ')

  if echo "$out" | grep -q "test result: FAILED"; then
    echo "$name :: RED -> $failed"
    if [ "$expect" != "red" ]; then
      echo "$name :: STALE EXEMPTION -- this guard is now load-bearing; delete its expectation"
      misses=$((misses + 1))
    fi
  elif ! echo "$out" | grep -q "test result:"; then
    echo "$name :: INCONCLUSIVE (the mutation itself did not compile)"
    inconclusive=$((inconclusive + 1))
  elif [ "$expect" != "red" ]; then
    echo "$name :: GREEN - VACUOUS, accepted (${expect#vacuous:})"
  else
    echo "$name :: GREEN - VACUOUS (no test can tell this guard from its absence)"
    vacuous=$((vacuous + 1))
  fi
  restore
}

E=src/wallet/enforcer.rs
S=src/wallet/summary.rs
M=src/wallet/money_signer.rs

probe "G7  an undeclared intent escalates" $E \
  'self.auto_send.configured_limits(op_class)' \
  'self.auto_send.configured_limits(match op_class {
            SpendOpClass::Undeclared => SpendOpClass::Tip,
            declared => declared,
        })'

# G2 is knowingly VACUOUS against dig-wallet-backend >= 0.16.1, and provably so rather than
# untested: the driver accumulates every created XCH coin plus the fee through a fallible
# `accumulate` and then requires `xch_in == xch_out + fee`, so this crate's native total -- a subset
# of those coins plus that fee -- is bounded by `xch_in` and cannot overflow. The guard is kept as
# defence-in-depth because that proof lives inside a dependency. What IS pinned is the boundary:
# `a_spend_whose_output_amounts_overflow_is_never_approved` asserts it from both sides, against the
# real dependency. The exemption below still expires by itself the moment the guard goes RED.
probe "G2  custody total is CHECKED, not saturating" $S \
  'let native_total_mojos = summary.checked_native_total_mojos()?;' \
  'let native_total_mojos = summary.native_total_mojos();' \
  'vacuous:unreachable given dig-wallet-backend >=0.16.1; proof in summary.rs DerivedSpend::derive'

probe "G19 input coin amounts must sum in a u64" $S \
  'coin_spends
        .iter()
        .try_fold(0u64, |sum, spend| sum.checked_add(spend.coin.amount))
        .ok_or_else(|| {' \
  'coin_spends
        .iter()
        .try_fold(0u64, |sum, spend| Some(sum.wrapping_add(spend.coin.amount)))
        .ok_or_else(|| {'

probe "G13 the rolling projection is checked, not wrapped" $E \
  '.try_fold(total, |sum, record| sum.checked_add(record.mojos))' \
  '.try_fold(total, |sum, record| Some(sum.wrapping_add(record.mojos)))'

# The three guards this fix round added. Each is neutralized into the exact pre-fix behaviour, so a
# GREEN here would mean the round shipped a guard nothing holds.

probe "G20 every output that leaves is counted, hinted or not" $S \
  '.chain(effect.change.iter())' \
  ''

probe "G21 a relocked session cannot sign" $M \
  'if !self.residency.is_live() {
            return Err(AccountError::Locked);
        }' \
  ''

probe "G22 an approval is admitted only by the wallet its gate ruled for" $M \
  'approval
            .scope()
            .assert_signable_by(self.profile_ix, self.wallet_puzzle_hash())?;' \
  ''

A=src/wallet/approval.rs

# ---------------------------------------------------------------- the derivation + destination rules

probe "G1  the gate refuses an unaccountable spend" $S \
  '    analyze(coin_spends)
        .map_err(|e| AccountError::Spend(format!("cannot derive spend summary: {e}")))' \
  '    Ok(analyze(coin_spends).unwrap_or(SpendEffect {
        recipients: vec![],
        change: vec![],
        fee: 0,
    }))'

probe "G23 only a PROVEN p2 destination counts as returning to the spender" $S \
  'let returns_to_spender = p2_destinations(coin_spends);' \
  'let returns_to_spender: BTreeSet<Bytes32> =
            coin_spends.iter().map(|s| s.coin.puzzle_hash).collect();'

probe "G3  the vault arm runs the destination rule" $E \
  'self.reject_vault_outflow_to_anyone_but_the_hot_wallet(&derived.summary)?;' \
  ''

# Neutralized by COLLAPSING the outcome rather than by removing the decode: an undecodable destination
# stops being distinguishable from a forbidden one, which is the mistake a future author would make.
probe "G4  an undecodable destination is indeterminate" $E \
  'AccountError::PolicyIndeterminate(format!(
                    "a vault spend pays {:?}, which is not a decodable address' \
  'AccountError::PolicyDenied(format!(
                    "a vault spend pays {:?}, which is not a decodable address'

probe "G5  the vault may pay ONLY the hot wallet" $E \
  'if address.puzzle_hash != self.hot_wallet_puzzle_hash {' \
  'if false {'

probe "G17 no gate may be built on an undecodable hot wallet" $E \
  'let hot_wallet = Address::decode(hot_wallet_address).map_err(|e| {' \
  'let hot_wallet = Address::decode(hot_wallet_address)
            .or_else(|_| Address::decode(&Address::new(Bytes32::new([7u8; 32]), "xch".to_string()).encode().unwrap()))
            .map_err(|e| {'

# ------------------------------------------------------------------------- the auto-send bounds

probe "G6  the global auto-send off switch" $E \
  'if !self.auto_send.enabled {
            return self.escalate(coin_spends, derived);
        }' \
  ''

probe "G8  a disabled op class escalates" $E \
  'if !limits.enabled {
            return self.escalate(coin_spends, derived);
        }' \
  ''

probe "G9  value no mojo limit can bound is indeterminate" $E \
  'self.reject_amounts_no_mojo_limit_can_bound(&derived.summary)?;' \
  ''

probe "G10 the per-transaction limit" $E \
  'if derived.native_total_mojos > limits.per_tx_limit_mojos {' \
  'if false {'

# ------------------------------------------------------------------------- the rolling window

probe "G11 a zero-length rolling window is indeterminate" $E \
  'if self.auto_send.period_seconds == 0 {
            return Err(AccountError::PolicyIndeterminate(
                "the auto-send period is zero seconds long, so no window exists to measure the cap \
                 over; the cap cannot be evaluated"
                    .to_string(),
            ));
        }' \
  ''

probe "G12 the rolling window expires entries" $E \
  'recent.retain(|record| record.at_unix.saturating_add(self.auto_send.period_seconds) > now);' \
  ''

probe "G14 the rolling period cap" $E \
  'if projected > self.auto_send.period_cap_mojos {' \
  'if false {'

probe "G15 a zero charge leaves no ledger record" $E \
  'if total > 0 {' \
  'if true {'

probe "G18 an unreadable clock refuses" $E \
  'let now = self.clock.now_unix()?;
        let mut recent = self.recent.lock().map_err(|_| {' \
  'let now = self.clock.now_unix().unwrap_or(0);
        let mut recent = self.recent.lock().map_err(|_| {'

probe "G25 the ledger cannot grow past MAX_LEDGER_ENTRIES" $E \
  'if recent.len() >= MAX_LEDGER_ENTRIES {' \
  'if false {'

# ------------------------------------------------------------- consent, and the attention budget

probe "G16 a declined ceremony denies rather than approving" $A \
  'SpendDecision::Decline(reason) => Err(AccountError::UserDeclined(format!(' \
  'SpendDecision::Decline(reason) => Ok::<SpendApproval, AccountError>(SpendApproval { inner: self.inner })
                .map_err(|_| AccountError::UserDeclined(format!('

probe "G24 the confirmation-prompt ceiling" $E \
  'if prompts.len() as u64 >= u64::from(self.auto_send.max_confirmations_per_period) {' \
  'if false {'

echo
echo "SUMMARY: $misses pattern-miss, $inconclusive inconclusive, $vacuous vacuous"
if [ $((misses + inconclusive + vacuous)) -ne 0 ]; then
  echo "FAIL: every guard must be load-bearing and every probe must actually run."
  exit 1
fi
echo "PASS: every probed guard is load-bearing."
