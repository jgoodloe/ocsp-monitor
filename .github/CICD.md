# CI/CD & security pipeline

Every change is tested and CVE-scanned, the image build is verified, and
**nothing reaches a release until it passes the full gate and you approve it.**

## What triggers what

| Trigger | Workflow | What runs | Result |
|---|---|---|---|
| Open/update a PR | `ci.yml` | `test` + `security` (pip-audit + Trivy) + `build` (image build + Trivy image scan) | PR is mergeable only if all three are green |
| Merge to `main` | `ci.yml` | same gate, then `publish-edge` | pushes a **non-release** `:edge` image (and `:main-<sha>`) — for testing, not production |
| A dependency CVE gets a fix | `dependabot.yml` (security updates) | opens a bump PR → `ci.yml` runs | patch/minor auto-merges (`dependabot-automerge.yml`) once green; **major** waits for you |
| Daily | `security-scan.yml` | pip-audit + Trivy on the pinned deps and the live `:latest` | if vulnerable with a fix available → opens/updates a **`security` alert issue** |
| Weekly | `ci.yml` (schedule) | full gate + `publish-edge` | rebuilds `:edge` on the latest patched base image |
| Push a `vX.Y.Z` tag, or run **Actions → Release** | `release.yml` | full gate (`ci.yml`) → **approval** → publish | releases `:vX.Y.Z` + `:latest` and a GitHub Release — only after you approve |

### Image tags
- `:edge`, `:main-<sha>` — automatic, gated on CI. **Not** for production.
- `:latest`, `:vX.Y.Z` — approved releases only. This is what production / the
  optional Watchtower service pulls.

## Releasing

1. `git tag v1.2.3 && git push origin v1.2.3` (or **Actions → Release → Run workflow**).
2. The full gate runs — tests, CVE/security scan, and a real image build must all pass.
3. The `publish` job pauses on the **`production`** environment and sends you an
   approval request (email + web). **You** decide whether it ships.
4. On approval: `:v1.2.3` + `:latest` are pushed and a GitHub Release is created.

If anything in the gate fails, there is no release — fix it and re-tag.

## One-time repo settings (required — not configurable in files)

1. **Settings → Code security** → enable *Dependabot alerts* + *Dependabot security updates*.
2. **Settings → General → Pull Requests** → *Allow auto-merge*.
3. **Branch protection on `main`** → require the **`test`**, **`security`**, and
   **`build`** status checks (from `ci.yml`).
4. **Settings → Environments → `production`** → add yourself as a **Required
   reviewer**. This is the release approval/alert gate; without it, releases
   would publish without pausing.
