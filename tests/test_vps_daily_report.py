#!/usr/bin/env python3
"""Regression tests for the VPS daily report collector."""

from __future__ import annotations

import pathlib
import sys
import unittest


ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

from vps_daily_report import parse_status  # noqa: E402


class ParseStatusTests(unittest.TestCase):
    def test_parses_interfaces_without_probe_responder(self) -> None:
        status = parse_status(
            """\
 Transport Instance aabbccdd running for 2 days

 Primary Backbone
    Status    : Up
 BackboneInterface/10001
    Status    : Up
 Named Peer
    Status    : Down
"""
        )

        self.assertEqual(status["transport_uptime"], "2 days")
        self.assertEqual(status["primary_peer_name"], "Primary Backbone")
        self.assertTrue(status["primary_peer_up"])
        self.assertEqual(status["backbone_up_count"], 1)
        self.assertEqual(status["named_peer_up_count"], 0)

    def test_ignores_probe_responder_transport_metadata(self) -> None:
        status = parse_status(
            """\
 Transport Instance aabbccdd running for 3 days
   Probe responder at 0123456789abcdef

 Primary Backbone
    Status    : Up
 BackboneInterface/10002
    Status    : Up
 Named Peer
    Status    : Up
"""
        )

        self.assertEqual(status["transport_uptime"], "3 days")
        self.assertEqual(status["primary_peer_name"], "Primary Backbone")
        self.assertTrue(status["primary_peer_up"])
        self.assertEqual(status["backbone_up_count"], 1)
        self.assertEqual(status["named_peer_up_count"], 1)


if __name__ == "__main__":
    unittest.main()
