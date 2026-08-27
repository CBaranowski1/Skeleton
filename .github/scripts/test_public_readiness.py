from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path
from types import ModuleType


SCRIPT_PATH = Path(__file__).with_name('public_readiness.py')


def load_scanner() -> ModuleType:
    spec = importlib.util.spec_from_file_location('skeleton_public_readiness', SCRIPT_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError('public_readiness_import_failed')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


SCANNER = load_scanner()


def labels_for(value: str) -> set[str]:
    return {
        label
        for label, pattern in SCANNER.CONTENT_PATTERNS
        if pattern.search(value)
    }


class PublicReadinessPatternTests(unittest.TestCase):
    def test_provider_and_private_material_patterns_are_detected(self) -> None:
        cases = {
            'private key marker': '-----BEGIN ' + 'PRIVATE KEY-----',
            'age secret key': 'AGE-' + 'SECRET-KEY-1' + ('A' * 32),
            'GitHub token': 'gh' + 'p_' + ('A' * 36),
            'GitLab token': 'gl' + 'pat-' + ('A' * 24),
            'AWS access key': 'AK' + 'IA' + ('A' * 16),
            'OpenAI-style key': 'sk-' + ('A' * 24),
            'Anthropic key': 'sk-' + 'ant-' + ('A' * 24),
            'Google API key': 'AI' + 'za' + ('A' * 35),
            'Hugging Face token': 'hf_' + ('A' * 32),
            'npm token': 'npm_' + ('A' * 36),
            'PyPI token': 'pypi-' + 'AgEIcHlwaS5vcmc' + ('A' * 24),
            '1Password service token': 'ops_' + ('A' * 43),
            'SendGrid token': 'SG.' + ('A' * 16) + '.' + ('B' * 16),
            'Slack token': 'xox' + 'b-' + ('A' * 24),
            'Stripe API key': 'sk_' + 'live_' + ('A' * 24),
            'Twilio API key': 'SK' + ('A' * 32),
            'Azure storage account key': 'Account' + 'Key=' + ('A' * 44) + '=',
            'credentialed URL': 'https://user:' + ('A' * 24) + '@example.invalid/path',
        }

        for expected_label, synthetic_value in cases.items():
            with self.subTest(case=expected_label):
                self.assertIn(expected_label, labels_for(synthetic_value))

    def test_short_placeholders_do_not_match_provider_patterns(self) -> None:
        placeholders = (
            'sk-' + ('A' * 12),
            'AK' + 'IA' + ('A' * 15),
            'npm_' + ('A' * 20),
            'AI' + 'za' + ('A' * 20),
            'https://example.invalid/no-credentials',
        )

        provider_labels = {
            label
            for label, _pattern in SCANNER.CONTENT_PATTERNS
            if 'path' not in label and 'IPv4' not in label
        }
        for placeholder in placeholders:
            with self.subTest(case='short-placeholder'):
                self.assertTrue(labels_for(placeholder).isdisjoint(provider_labels))


if __name__ == '__main__':
    unittest.main()
