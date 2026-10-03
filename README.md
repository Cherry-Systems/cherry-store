# Cherry Store

The app store for [Cherry OS](https://github.com/Cherry-Systems). Every app is an ordinary
Debian package (`.deb`) kept in this repository's
[Releases](https://github.com/Cherry-Systems/cherry-store/releases); [`index.json`](index.json)
lists them. Cherry OS installs them from the Cherry Store app or the terminal:

```sh
cherry install hello-cherry     # asks for your password when it needs it
cherry search paint
cherry update                   # everything you installed from the store
cherry remove hello-cherry
```

## How it's kept safe

Nobody reviews apps by hand. Instead:

- Each package is signed with its publisher's key. Later versions need the same key, so nobody
  else can take over a name.
- Every upload is scanned with ClamAV, and all packages are scanned again every night.
- Anything unusual a package does is recorded as a warning, and Cherry shows it before
  installing. That includes running its own install scripts, putting files outside `/opt` and
  `/usr`, setuid programs, sharing a name with a Debian package, and replacing other packages.
- Anyone can [report a package](../../issues/new?template=report.yml). Harmful ones are taken
  down with the *Publish* workflow (`takedown`).

## Publishing

On Cherry OS, run `cherry init` in your app's folder, fill in `cherry.toml`, then:

```sh
cherry build                   # makes NAME_VERSION_ARCH.deb
cherry publish --github        # uses your GitHub account (via the gh command)
cherry publish --cherry        # or your Cherry account
```

With `--github`, the `.deb` goes to a release in your own `cherry-packages` repository and an
issue titled `Publish: NAME VERSION` is opened here. With `--cherry`, Cherry Cloud keeps the
upload just long enough for this repository to fetch it. Either way the
[Publish workflow](.github/workflows/publish.yml) checks the signature, scans the package, copies
it into a release here and adds it to `index.json`, then reports back. You can also publish a
`.deb` you built some other way: `cherry publish --github my-app_1.0_amd64.deb`.

To withdraw a version, run `cherry yank NAME VERSION`.

## Files

- `tools/store.py` checks packages and keeps `index.json`.
- `tools/pipeline.py` handles each publish/withdraw request in GitHub Actions.
- `.github/workflows/rescan.yml` is the nightly virus scan.
