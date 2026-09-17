# Contributor Workflow

Read this before you touch any issue. It explains what an issue actually is, why it exists, and the exact steps to take it from "assigned to me" to "done" — for human teammates and for AI coding agents alike.

**The short version: reading an issue and clicking "Close" is never the correct way to finish it.** An issue is only finished when a pull request that says `Closes #<number>` is reviewed and merged into `main`. If you close an issue any other way, it will get reopened, because there's no proof the work actually happened.

## What is an issue?

Every issue in this repository is one piece of work from `ISSUE_PLAN.md`, the project's master plan. Its title looks like `[Plan #07] Concurrent worker model with safe argument ownership` — the `[Plan #NN]` lets you cross-reference the original written plan even though GitHub's own issue number is different.

Each issue tells you:

- **Why this exists** — the real reason this work matters, not just "because the plan says so."
- **What to build** — the concrete thing you're making.
- **Acceptance criteria** — how you (and a reviewer) will know it's actually done.
- **Depends on** — which other issues must be merged first. If this says "Blocked by #4", do not start until #4 is merged into `main`.
- **Out of scope** (when present) — what this issue deliberately does *not* cover, so you don't over-build.

## Step-by-step: taking an issue from assigned to merged

### 1. Read the whole issue first

Not just the title. Read "Why this exists" and "Acceptance criteria" especially — they tell you what "done" means before you write a line of code.

### 2. Check "Depends on" before doing anything

- If it says a specific issue number is blocking you, open that issue. If it's still open, that work isn't merged into `main` yet — you either wait, or go help finish it first.
- If the blocking issue **has** been merged since you last looked, make sure your local `main` is up to date before you branch (see step 3). If you already have a branch that's now behind, bring it up to date by rebasing:
  ```sh
  git checkout main
  git pull origin main
  git checkout your-branch-name
  git rebase main
  ```
  Fix any conflicts Git shows you, then continue with `git rebase --continue`.

### 3. Create a branch off `main`

Never work directly on `main` — it's protected and direct pushes are blocked anyway. Always start fresh from the latest `main`:

```sh
git checkout main
git pull origin main
git checkout -b type/short-description
```

Pick a `type/` prefix that matches the work:

- `feat/` — new functionality
- `fix/` — bug fix
- `docs/` — documentation only
- `test/` — tests only
- `chore/` — build, tooling, config

Example, for Issue #2 (repository foundation and build): `git checkout -b chore/build-verification`.

### 4. Do the work described in the issue

Write the code, config, or docs the issue asks for. Keep the change scoped to what the issue describes — if you notice unrelated problems, open a new issue for them instead of fixing everything at once.

### 5. Test and verify — do not skip this

Every issue's "Acceptance criteria" (and "Verification" section, when present) tells you exactly what to check. At minimum, before opening a pull request:

```sh
make clean && make
make test
make sanitize
```

Run any manual verification the issue describes too (for example: "send a request with `nc localhost 8080` and confirm you get a valid response"). Write down what you actually saw — you'll need it in the pull request.

### 6. Commit your work

```sh
git add <the files you changed>
git commit -m "type: short description of what changed"
```

Use the same `type:` prefixes as branch names (`feat:`, `fix:`, `docs:`, `test:`, `chore:`).

### 7. Push your branch and open a pull request

```sh
git push -u origin type/short-description
gh pr create --base main --head type/short-description --title "..."
```

This loads the repository's pull request template automatically. Fill in **every** section — this is required, not optional, for humans and AI agents alike:

- **Files created or changed**: a table listing every file you touched, what changed, and why. A reviewer should never have to guess your intent from the raw diff.
- **Test results**: paste what you actually ran and what it actually said (e.g. "`make test` → all 12 checks passed"), not just a checked box.
- **Security and privacy impact**: say what it is, or say there is none.
- **Closes #\<issue-number\>**: this is the line that makes GitHub automatically close the issue the moment this pull request merges. Get the issue number right — this is the only correct way an issue gets closed.

### 8. Get a review

`main` requires at least one approving review plus passing CI checks before anything can merge. You cannot approve your own pull request — GitHub blocks that by design — so ask a teammate to review it, or review theirs while you wait.

### 9. Merge only after review + CI are both green

Once approved and CI passes, merge the pull request (normally, not with any bypass option — bypassing is reserved for the repository owner in genuine emergencies). Because the pull request said `Closes #<number>`, the issue closes itself automatically. You don't click "Close" on the issue — the merge does it for you.

## Quick reference

| Situation | What to do |
| --- | --- |
| Issue lists a "Depends on" that's still open | Wait, or help finish that issue first — do not start |
| Issue lists a "Depends on" that just merged | `git pull origin main` before branching, or `git rebase main` if you already have a branch |
| You think you're done | Re-read "Acceptance criteria" on the issue and confirm each one, in writing, before opening the pull request |
| You want to close an issue | You don't — you merge a pull request that says `Closes #<number>`, and GitHub closes it for you |
| You're not sure if your pull request is complete | Compare it against `.github/pull_request_template.md` — every section must be filled in with real content |
