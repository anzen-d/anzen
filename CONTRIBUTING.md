# Contributing to Anzen

Thanks for helping! Bug reports, new checks, false-positive fixes and distro
or Windows coverage are all welcome. By taking part you agree to follow the
[Code of Conduct](CODE_OF_CONDUCT.md).

## Ground rules

- **Generic only.** Anzen must work on any host. No hostnames, IPs, domains,
  tokens or site-specific paths in the code, docs or tests. Site-specific
  checks belong in a `CUSTOM_CHECKS_DIR` module outside the repo.
- **No new runtime dependencies** for the core. Bash 4.2+ and coreutils;
  optional tools (trivy, docker, curl) must degrade to an `info` line when absent.
- **Never prompt.** Use `_priv` for privileged commands, never bare `sudo`.
- **Keep finding IDs stable.** An ID is derived from the section name and the
  message text (numbers like percentages, sizes, durations and counts are
  normalised). Rewording a message changes its ID, which breaks users' accept
  files and baselines — only do it on purpose and note it in the changelog.

## Development setup

```bash
make lint      # shellcheck (warnings fail)
make test      # bats test suite
make ci        # both
make matrix    # run anzen in Debian/Ubuntu/Fedora/Rocky/Alpine/Arch/openSUSE containers (needs docker)
```

No local bats/shellcheck? The CI workflow streams the tree into the
`koalaman/shellcheck-alpine` and `bats/bats` containers — copy those commands.

Windows edition: `windows/anzen.ps1` must stay Windows PowerShell 5.1
compatible (no `??`, ternaries or `-Parallel`) and saved as UTF-8 **with BOM**.
Tests: `Invoke-Pester windows/tests`; lint: `Invoke-ScriptAnalyzer windows/anzen.ps1`.

## Adding a Linux check module

1. Create `lib/checks/<name>.sh` defining `run_<name>_check`.
2. Use the helpers from `lib/output.sh`:
   ```bash
   run_example_check() {
       section "Example"
       if something_bad; then
           fail "Short, specific message: $path"
           remedy "exact command that fixes it"
       else
           ok "Example looks fine"
       fi
   }
   ```
   `remedy` must follow the `fail`/`warn` it belongs to.
3. Add `<name>` to `ALL_MODULES` in `anzen.sh`, the TUI list in `anzen-tui.sh`,
   both completions, and the module table in `README.md`
   (`tests/test_cli.bats` fails if a module is missing from `ALL_MODULES`).
4. Add bats tests in `tests/` — fake commands with shell functions rather than
   relying on the CI host's state.
5. Run `make ci` and `make matrix`.

Severity guide: **FAIL** = exploitable or clearly wrong, **WARN** = weaker than
recommended or needs review, **INFO** = context only, **OK** = verified good.

## Pull requests

- One topic per PR; include a `CHANGELOG.md` entry under an "Unreleased" heading.
- Describe how you tested (distros, Windows version).
- CI must be green.

## Reporting false positives

Open an issue with the finding text, its ID, your distro/version and why it is
wrong. False positives are bugs.
