from __future__ import annotations

import unittest
from unittest.mock import AsyncMock, patch

from discord_bypass.__main__ import _select_split_mode
from discord_bypass.diagnostics import DiagnosticResult


class _FakeProxy:
    def __init__(self) -> None:
        self.modes: list[str] = []

    def set_split_mode(self, mode: str) -> None:
        self.modes.append(mode)


class MainTests(unittest.IsolatedAsyncioTestCase):
    async def test_auto_mode_falls_back_and_keeps_passing_strategy(self) -> None:
        proxy = _FakeProxy()
        expected = DiagnosticResult("TLSv1.3", "cipher", "HTTP/1.1 200 OK")
        probe = AsyncMock(side_effect=[TimeoutError("blocked"), expected])

        with patch("discord_bypass.__main__._test_split_mode", probe):
            result = await _select_split_mode(proxy, "auto")  # type: ignore[arg-type]

        self.assertEqual(result, expected)
        self.assertEqual(proxy.modes, ["tcp-oob", "tls-record"])

    async def test_forced_mode_does_not_fall_back(self) -> None:
        proxy = _FakeProxy()
        probe = AsyncMock(side_effect=TimeoutError("blocked"))

        with patch("discord_bypass.__main__._test_split_mode", probe):
            with self.assertRaises(ConnectionError):
                await _select_split_mode(  # type: ignore[arg-type]
                    proxy,
                    "tcp-aggressive",
                )

        self.assertEqual(proxy.modes, ["tcp-aggressive"])


if __name__ == "__main__":
    unittest.main()
