# Public export tool

This private-side tool generates a new-history public candidate from one exact
canonical commit. It never copies the private repository's `.git` directory or
reads uncommitted working-tree content.

Every exported source path must appear explicitly in
`release/public-export-manifest.json` with its reviewed SHA-256 digest. The
exporter reads both the manifest and file bytes from the selected Git commit,
rejects private paths and unsafe file types, validates all hashes before
writing, and emits deterministic `PUBLIC-PROVENANCE.json` metadata.

Manifest digests cover canonical Git blob bytes, not potentially line-ending-
normalized working-tree bytes. Stage reviewed source changes before refreshing
their manifest digests, then commit the source and manifest together.

Run it with an output directory outside the canonical repository:

```powershell
python tools/public-export/export_public.py `
  --repo . `
  --source HEAD `
  --output C:\path\to\empty-public-candidate
```

The generated tree is only a candidate. It must still be initialized as new
Git history and pass the public-readiness, secret, dependency, license, build,
and test gates described in `PUBLICATION.md`. The exporter does not push or
change GitHub repository visibility.
