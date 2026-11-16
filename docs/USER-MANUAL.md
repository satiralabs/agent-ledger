# AgentLedger — User Manual

A simple guide. No technical background needed.

## What is AgentLedger?

Your AI agents do things: run commands, search, write files, query data.
AgentLedger keeps a notebook of those actions that **cannot be quietly
edited afterwards**. Every action is written down, linked to the one before
it, and signed with a secret key. If anyone changes an old page, the check
fails and you can see it.

Think of it as a receipt book where the pages are glued together: tear one
out or rewrite it, and the glue shows.

## Getting started

**Step 1 — create your ledger**

```
agent-ledger init
```

This creates two files:

- the ledger itself (your notebook), and
- a key file ending in `.key` next to it. **Keep this file safe and
  private**, like a password. It is the pen that signs every page.

**Step 2 — record an action**

```
agent-ledger log --agent coder-01 --action tool_call --payload '{"tool": "bash", "cmd": "git status"}'
```

**Step 3 — check the notebook**

```
agent-ledger verify
```

If it says **VERIFIED**, nothing in the ledger has been changed since it
was written.

## Using the screen (GUI)

```
agent-ledger serve
```

Then open **http://127.0.0.1:8765** in your browser.

- **Dashboard** — how many actions, how many agents, whether the chain is
  VERIFIED, and a simple form to record an action.
- **Ledger** — the list of actions, newest first. You can filter by agent.
- **Verify** — one button that checks the whole notebook, plus the
  "Merkle root", a single fingerprint for the whole ledger.
- **Receipts** — create a signed receipt for one important action.
- **Policy** — see what is blocked, and test an action before doing it.

The screen only works on your own computer (localhost). It has no
password, so do not open it to the internet.

## What is a policy?

Some actions are too dangerous to just record. AgentLedger checks first:

- **Blocked** — for example a command containing `rm -rf` (delete
  everything). The action is refused, **and the refusal itself is written
  in the ledger**, so you can see that someone tried.
- **Needs approval** — for example anything about transfers, deleting, or
  spending above the cost limit. It is refused until a person adds
  `--approve`.
- **Pass** — everything else. Recorded normally.

You can test without recording anything:

```
agent-ledger policy-check --tool bash --params '{"cmd": "rm -rf /"}'
```

## What is a receipt?

A receipt is extra proof for one action: *this agent, given this prompt,
used this tool and got this result* — signed, so it cannot be swapped
later. Add `--append` to also store the receipt inside the ledger.

## Sharing proof with someone else

```
agent-ledger export --out ./audit-bundle --zip
```

This makes a bundle with the ledger, a plain report, and the Merkle root.
The other person can run `agent-ledger verify` on it and check for
themselves — they do not have to trust you.

To prove that **one single action** is really in the ledger:

```
agent-ledger prove --block 3
```

## Troubleshooting

| Problem | What it means | What to do |
|---|---|---|
| "No signing key available" | The key file is missing and `AGENT_LEDGER_KEY` is not set | Run `agent-ledger init` in the same place, or restore the `.key` file from your backup |
| "WARNING … recorded UNSIGNED" | The action was written without a signature | Find or restore the key file; new actions will be signed again. Unsigned old actions still check as part of the chain |
| Verify says FAILED / "Hash tampering detected" | A block was changed after it was written | Do not trust that ledger. Restore it from a backup and compare Merkle roots |
| Verify says "Signatures: FAILED" | Blocks were signed with a different key, or signatures were forged | Check you are using the right key file for this ledger |
| Action refused with exit code 3 | Policy blocked it | Read the reason. The refusal is already recorded — that is expected |
| Action refused with exit code 4 | It needs a person's approval | If a person agrees, run the same command again with `--approve` |
| GUI page does not open | The server is not running, or the port is busy | Run `agent-ledger serve --port 8766` and open that port instead |
| Two programs writing at once | Normally fine — writes are locked one at a time | If verify ever fails right after heavy parallel use, report it; it should not happen |

## Good habits

1. Back up the ledger **and** its key file together.
2. Save the Merkle root somewhere else (even on paper). If the root you
   saved does not match later, the ledger changed.
3. Never share the key file. Anyone with it can sign fake actions.
4. Run `verify` before you rely on a report.
