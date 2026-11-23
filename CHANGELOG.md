# Changelog

## 1.0.0

First public release.

- `guardpost boot`: a report after every login of boots, time off, logins by
  method, failed attempts, wake-ups, USB storage, sudo, and changes to the
  places malware uses to stay on a machine.
- `guardpost scan` and a post-checkout hook: every `git clone` is checked for
  install hooks that download or run code, code hidden off the right edge of
  the screen, eval of encoded blobs, obfuscation, stealers, drop-box webhooks,
  reverse shells, miners, VS Code folder-open tasks, programs in the source,
  Trojan Source characters and look-alike package names.
- Layer 2: `npm/yarn/pnpm/bun install` and `pip install` are checked before
  and after. The dependency tree is resolved without running anything, looked
  up in OSV (malware and vulnerabilities), and the packages that run code on
  install are downloaded and read first.
- `guardpost sweep`, weekly: Ubuntu security updates (marked when on CISA KEV),
  installed pip/npm/cargo packages in OSV, connections to malware servers,
  odd processes, start-up entries, `dpkg --verify`, stray kernel modules,
  YARA and ClamAV.
- `guardpost update`, daily: threat feeds and new guardpost releases, checked
  by SHA-256 before they're installed.
