from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path


MAX_PUBLIC_FILE_BYTES = 10 * 1024 * 1024

REQUIRED_PATHS = (
    '.gitattributes',
    '.gitleaks.toml',
    '.gitignore',
    '.github/dependabot.yml',
    '.github/workflows/ci.yml',
    '.github/workflows/codeql.yml',
    '.github/workflows/dependency-review.yml',
    '.github/workflows/public-readiness.yml',
    'CODE_OF_CONDUCT.md',
    'CONTRIBUTING.md',
    'LICENSE',
    'PUBLICATION.md',
    'README.md',
    'SECURITY.md',
    'SECURITY-AUDIT.md',
)

DENIED_PREFIXES = (
    '.planning/',
    'validation/',
    'private/',
    'secrets/',
    'owner-private/',
    'public-export/',
    'public-mirror/',
)

DENIED_SUFFIXES = {
    '.7z',
    '.bin',
    '.bundle',
    '.ckpt',
    '.db',
    '.dll',
    '.dmp',
    '.dump',
    '.exe',
    '.ggml',
    '.gguf',
    '.gz',
    '.h5',
    '.jks',
    '.kdbx',
    '.key',
    '.npy',
    '.npz',
    '.onnx',
    '.ovpn',
    '.p12',
    '.p8',
    '.parquet',
    '.pdb',
    '.pem',
    '.pfx',
    '.pt',
    '.pth',
    '.rar',
    '.safetensors',
    '.sqlite',
    '.sqlite3',
    '.tfstate',
    '.tar',
    '.tflite',
    '.tgz',
    '.xz',
    '.zip',
}

DENIED_BASENAMES = {
    '.netrc',
    '.npmrc',
    '.pypirc',
    'auth.json',
    'credentials.json',
    'credentials.toml',
    'credentials.yaml',
    'credentials.yml',
    'kubeconfig',
    'service-account.json',
    'secrets.json',
    'secrets.toml',
    'secrets.yaml',
    'secrets.yml',
    'tokens.json',
    'tokens.toml',
    'tokens.yaml',
    'tokens.yml',
    'wallet.dat',
}

CONTENT_PATTERNS = (
    ('private key marker', re.compile(r'-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----')),
    ('age secret key', re.compile(r'\bAGE-SECRET-KEY-1[0-9A-Z]{20,}\b')),
    ('GitHub token', re.compile(r'\b(?:gh[oprsu]_[A-Za-z0-9_]{30,}|github_pat_[A-Za-z0-9_]{30,})\b')),
    ('GitLab token', re.compile(r'\bglpat-[A-Za-z0-9_-]{20,}\b')),
    ('AWS access key', re.compile(r'\b(?:AKIA|ASIA)[A-Z0-9]{16}\b')),
    ('OpenAI-style key', re.compile(r'\bsk-[A-Za-z0-9_-]{20,}\b')),
    ('Anthropic key', re.compile(r'\bsk-ant-[A-Za-z0-9_-]{20,}\b')),
    ('Google API key', re.compile(r'\bAIza[0-9A-Za-z_-]{35}\b')),
    ('Hugging Face token', re.compile(r'\bhf_[A-Za-z0-9]{30,}\b')),
    ('npm token', re.compile(r'\bnpm_[A-Za-z0-9]{36}\b')),
    ('PyPI token', re.compile(r'\bpypi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]{20,}\b')),
    ('1Password service token', re.compile(r'\bops_[A-Za-z0-9]{43,}\b')),
    ('SendGrid token', re.compile(r'\bSG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}\b')),
    ('Slack token', re.compile(r'\bxox[baprs]-[A-Za-z0-9-]{20,}\b')),
    ('Stripe API key', re.compile(r'\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,}\b')),
    ('Twilio API key', re.compile(r'\bSK[0-9A-Fa-f]{32}\b')),
    ('Azure storage account key', re.compile(r'(?i)\bAccountKey=[A-Za-z0-9+/]{40,}={0,2}')),
    ('credentialed URL', re.compile(r'(?i)\b(?:https?|ssh|postgres(?:ql)?|mysql)://[^/\s:@]+:[^/\s@]+@')),
    ('private user path', re.compile(r'(?i)(?:[A-Z]:[\\/](?:Users|Documents and Settings)[\\/]|/(?:home|Users)/[^/\s]+/)')),
    ('private IPv4 address', re.compile(r'(?<!\d)(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})(?!\d)')),
)

SELF_PATH = '.github/scripts/public_readiness.py'


def git_output(*args: str) -> bytes:
    return subprocess.check_output(('git', *args), stderr=subprocess.STDOUT)


def tracked_paths() -> list[str]:
    return [
        item.decode('utf-8', errors='strict').replace('\\', '/')
        for item in git_output('ls-files', '-z').split(b'\0')
        if item
    ]


def main() -> int:
    root = Path(git_output('rev-parse', '--show-toplevel').decode().strip()).resolve()
    tracked = tracked_paths()
    tracked_set = set(tracked)
    violations: list[tuple[str, str]] = []

    for required in REQUIRED_PATHS:
        if required not in tracked_set:
            violations.append((required, 'required public-release file is missing'))

    for relative in tracked:
        normalized = relative[2:] if relative.startswith('./') else relative
        lower = normalized.lower()
        path = (root / normalized).resolve()

        try:
            path.relative_to(root)
        except ValueError:
            violations.append((relative, 'path resolves outside the repository'))
            continue

        if any(lower.startswith(prefix) for prefix in DENIED_PREFIXES):
            violations.append((relative, 'private or generated path is denied in the public mirror'))

        basename = path.name.lower()
        if basename.startswith('.env') and basename != '.env.example':
            violations.append((relative, 'environment file is denied'))
        if basename in DENIED_BASENAMES:
            violations.append((relative, 'credential or secret filename is denied'))
        if path.suffix.lower() in DENIED_SUFFIXES:
            violations.append((relative, f'denied file type: {path.suffix.lower()}'))

        if not path.exists():
            violations.append((relative, 'tracked path is missing from the worktree'))
            continue
        if path.is_symlink():
            violations.append((relative, 'symlinks require explicit public review'))
            continue
        if not path.is_file():
            continue

        size = path.stat().st_size
        if size > MAX_PUBLIC_FILE_BYTES:
            violations.append((relative, f'file exceeds {MAX_PUBLIC_FILE_BYTES} bytes'))
            continue

        if relative == SELF_PATH:
            continue

        data = path.read_bytes()
        if b'\0' in data:
            violations.append((relative, 'binary content requires explicit provenance review'))
            continue
        try:
            text = data.decode('utf-8', errors='strict')
        except UnicodeDecodeError:
            violations.append((relative, 'non-UTF-8 content requires explicit provenance review'))
            continue
        for label, pattern in CONTENT_PATTERNS:
            if pattern.search(text):
                violations.append((relative, label))

    unique = sorted(set(violations))
    if unique:
        print(f'Public-readiness check failed with {len(unique)} violation(s):')
        for relative, reason in unique:
            print(f'  - {relative}: {reason}')
        print('Matched secret material is intentionally not printed.')
        return 1

    print(f'Public-readiness check passed for {len(tracked)} tracked files.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
