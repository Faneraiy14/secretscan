# secretscan

*[Українською](README.uk.md)*

A CLI tool that finds accidentally committed secrets (API keys,
tokens, private keys) in your project's files — before they land in
git along with the rest of the code.

## Why

A token pasted straight into the code "temporarily, I'll move it out
later" stays in the git history forever, even if you delete it in the
next commit. `secretscan` catches this before the commit (`--fix`
isn't offered here — a secret can't be "auto-fixed", only removed by
hand and rotated).

## Install

```bash
git clone https://github.com/Faneraiy14/secretscan.git
cd secretscan
composer install --no-dev
```

Or without composer — there are no dependencies, `php bin/secretscan`
works right out of the clone.

## Usage

```bash
php bin/secretscan                      # current folder
php bin/secretscan src/                 # a specific folder or file
php bin/secretscan --json               # machine-readable output for CI
```

`.git/`, `node_modules/`, `vendor/` are always skipped — they hold
either internal data or someone else's code.

## What it catches

| Rule | Example |
|---|---|
| GitHub Personal Access Token | `ghp_...`, `github_pat_...` |
| AWS Access Key ID | `AKIA...` |
| Slack Token | `xoxb-...`, `xoxp-...` |
| Stripe Live Key | `sk_live_...`, `pk_live_...` |
| Google API Key | `AIza...` |
| Anthropic API Key | `sk-ant-...` |
| OpenAI API Key | `sk-...`, `sk-proj-...` |
| Database Connection String | password right in the URL: `postgres://<user>:<pass>@host`, `mysql://...`, `mongodb(+srv)://...`, `redis://...` |
| Private key | a `-----BEGIN ... PRIVATE KEY-----` block |
| Generic Bearer Token | `Bearer eyJ...` |
| Generic Secret Assignment | `password = "..."`, `api_key: "..."` |
| High Entropy String (Shannon) | any string literal ≥20 characters with entropy ≥4.0 bits/char — catches custom tokens with no known format |

Values that look like placeholders (`your_key_here`, `changeme`,
`example`, `<...>`, `{{...}}`, etc.) are skipped — otherwise every
`.env.example` would fail the check.

The entropy check is a heuristic, not an exact detector: real text
(sentences, identifiers) has noticeably lower entropy per character
than random base64/hex, so false positives are rare but possible —
mark those with `secretscan:ignore`.

## Redaction

A found value is always shown partially in the console and in
`--json`: the first and last 4 characters, the rest replaced with
asterisks. Enough to recognize it's "the same" secret, not enough for
someone to read it off a CI log screenshot.

## False positives

If a line intentionally contains an example/fixture that looks like a
secret (tests, docs), add a `secretscan:ignore` comment at the end of
the line and it'll be skipped:

```php
$fakeToken = "ghp_exampleexampleexampleexampleexam1"; // secretscan:ignore
```

## In CI

A ready-made GitHub Action — drop it into any repo without a
composer install, PHP is set up automatically:

```yaml
- uses: actions/checkout@v4
- uses: Faneraiy14/secretscan@main
  with:
    path: .   # optional, defaults to '.'
```

The step fails (exit 1) if suspicious values are found — blocks the
merge via a required status check in the GitHub branch settings.

Or manually, without the composite action:

```yaml
- run: php bin/secretscan --json || exit 1
```

Exit code 1 if something was found, 0 if clean, 2 for an error (e.g.
a nonexistent path).

## Tests

```bash
php tests/run.php
```

39 checks: each rule tested individually (including the entropy one),
value redaction, placeholders, binary files, folder recursion and
exclusion, `secretscan:ignore`, deduplication of regex/entropy on the
same value, CLI-level behavior (`--json`, exit codes, `--help`) via a
real process call.

## License

MIT — see [LICENSE](LICENSE). Author: Faneraiy14.
