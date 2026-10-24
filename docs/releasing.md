# Publishing a release (and counting downloads)

Downloads are counted **at the source**: GitHub keeps a counter for every file attached to a release, and shows it on the
release page. Nothing in SwarmSentinel phones home, so the count says how many times a file was downloaded, not who or where.

The repository people download from must be **public**. Use the sanitized repository (made with `deploy/export_public.py`),
not the private one: a private repository cannot serve downloads to anyone else.

## Steps

1. Build the package on a machine that has the repository:
   ```
   deploy/make-release.sh --out dist --version v0.4.0
   ```
   This writes `dist/swarmsentinel-v0.4.0.tar.gz` and its `.sha256` checksum. The version you give here **must be exactly the
   tag you use on GitHub in step 3**: installed copies compare the two to decide whether an update exists.
2. On GitHub, open the public repository, then **Releases**, then **Draft a new release**.
3. Make a tag such as `v0.4.0`, a title, and a few lines on what changed.
4. Attach these files (drag them into the release page):
   - `swarmsentinel-<version>.tar.gz`, the package
   - `swarmsentinel-<version>.tar.gz.sha256`, so people can check it arrived intact
   - `install-windows.ps1`, the one-command installer for Windows (also inside the package, but Windows users need it first)
5. Publish the release.

## Reading the counts

On the release page, GitHub shows each file's download count. For a summary of every release in the terminal:

```
deploy/release-stats.sh OWNER/REPO
```

## What the count means

- It counts downloads of the file, including your own tests and anyone who downloads twice.
- It does not tell you how many installs succeeded, or on what.
- That is the trade for not tracking anyone. If you ever want install counts, it has to be an opt-in message the customer
  chooses to send, and it needs a collector that does not exist yet.

## How installed machines update

An install unpacked from a package has no git history, so `deploy/update.sh` hands it to `deploy/update-package.sh`. That
script asks GitHub for the **newest release** of the repository (set `SSAI_UPDATE_REPO=OWNER/REPO` to change it, or
`SSAI_UPDATE_CHECK=off` to turn the check off), then:

1. downloads the package over https and checks it against the published `.sha256` file;
2. refuses it if it is not a SwarmSentinel package, or if the version inside is not the release's tag;
3. saves the current version to `.update-backup.tar.gz`;
4. replaces the code, never touching `backend/instance` (database, keys, settings), `.env`, `logs` or the virtualenv;
5. runs the new version's own tests, restarts the services and waits for them to answer;
6. if the tests or the restart fail, puts the saved version back.

`deploy/update.sh --check` only reports (exit 10 means a newer release exists). The Settings page shows an "Update available"
notice on package installs; the update itself is always run on the machine, never from the browser.

**An install made before this updater existed** has no `update-package.sh`. Bring it up to date once, from a newer package:

```
tar xzf swarmsentinel-<version>.tar.gz -C /tmp
/tmp/SwarmSentinel/deploy/update-package.sh --target /opt/ssai-src/SwarmSentinel
```

(`--target` is the folder the old install lives in.) After that, plain `deploy/update.sh` works.

Stage 2, not built yet: sign each release and have installs refuse anything not signed by you. A checksum proves the download
arrived intact; only a signature proves it came from you.
