import argparse
import json
import unittest
from unittest.mock import patch

import pmtr


class KnownNodeParsingTests(unittest.TestCase):
    def test_mixed_forms_are_flattened_and_deduplicated(self):
        self.assertEqual(
            pmtr._parse_known_nodes(
                [
                    ["10.0.0.1", "192.0.2.1,198.51.100.2"],
                    ["10.0.0.1", "203.0.113.4"],
                ]
            ),
            ["10.0.0.1", "192.0.2.1", "198.51.100.2", "203.0.113.4"],
        )

    def test_invalid_and_ipv6_addresses_are_rejected(self):
        for value in ("not-an-ip", "2001:db8::1", "10.0.0.1,"):
            with (
                self.subTest(value=value),
                self.assertRaises(argparse.ArgumentTypeError),
            ):
                pmtr._parse_known_nodes([[value]])


class KnownNodeMergeTests(unittest.TestCase):
    def setUp(self):
        self.hops = [
            pmtr.HopStats(1, "10.0.0.1", "gateway"),
            pmtr.HopStats(2, "*", "*"),
            pmtr.HopStats(3, "203.0.113.10", "destination"),
        ]

    @patch("pmtr._resolve_hostname", return_value="known-router")
    def test_gap_is_replaced_with_manual_node(self, _resolve):
        warnings = pmtr._merge_known_nodes(self.hops, [("192.0.2.2", 2)])

        self.assertEqual(warnings, [])
        self.assertEqual(self.hops[1].ip, "192.0.2.2")
        self.assertEqual(self.hops[1].hostname, "known-router")
        self.assertTrue(self.hops[1].manual)

    def test_matching_discovered_node_is_marked_manual(self):
        warnings = pmtr._merge_known_nodes(self.hops, [("10.0.0.1", 1)])

        self.assertEqual(warnings, [])
        self.assertTrue(self.hops[0].manual)

    @patch("pmtr._resolve_hostname", side_effect=lambda ip: ip)
    def test_conflicts_failures_and_beyond_route_are_omitted(self, _resolve):
        warnings = pmtr._merge_known_nodes(
            self.hops,
            [
                ("192.0.2.2", 2),
                ("192.0.2.3", 2),
                ("198.51.100.1", 1),
                ("198.51.100.2", 4),
                ("198.51.100.3", None),
            ],
        )

        self.assertEqual(self.hops[1].ip, "192.0.2.2")
        self.assertEqual(len(warnings), 4)
        self.assertIn("occupied hop 2", warnings[0])
        self.assertIn("occupied hop 1", warnings[1])
        self.assertIn("beyond the discovered route", warnings[2])
        self.assertIn("unable to determine TTL", warnings[3])


class _FakeRawSocket:
    def __init__(self, target_ip):
        self.target_ip = target_ip
        self.ttl = 0
        self.ident = 0
        self.recv_count = 0

    def setsockopt(self, _level, _option, value):
        self.ttl = value

    def settimeout(self, _timeout):
        pass

    def sendto(self, packet, _target):
        self.ident = int.from_bytes(packet[4:6], "big")

    def recvfrom(self, _size):
        self.recv_count += 1
        if self.recv_count > 1:
            raise TimeoutError
        packet = bytearray(28)
        packet[20] = pmtr.ICMP_ECHO_REPLY
        if self.ttl == 1:
            packet[24:26] = ((self.ident + 1) & 0xFFFF).to_bytes(2, "big")
            return bytes(packet), (self.target_ip, 0)
        if self.ttl == 2:
            packet[24:26] = self.ident.to_bytes(2, "big")
            return bytes(packet), ("192.0.2.254", 0)
        packet[24:26] = self.ident.to_bytes(2, "big")
        return bytes(packet), (self.target_ip, 0)

    def close(self):
        pass


class KnownNodeProbeTests(unittest.TestCase):
    def test_probe_requires_matching_source_and_identifier(self):
        target = "198.51.100.8"
        with patch("pmtr.socket.socket", side_effect=lambda *_args: _FakeRawSocket(target)):
            ttl = pmtr._probe_known_node_ttl(target, 3, 0.01, 56, 1234)
        self.assertEqual(ttl, 3)

    def test_probe_stops_at_max_hops(self):
        target = "198.51.100.8"
        with patch("pmtr.socket.socket", side_effect=lambda *_args: _FakeRawSocket(target)):
            ttl = pmtr._probe_known_node_ttl(target, 2, 0.01, 56, 1234)
        self.assertIsNone(ttl)


class ManualProvenanceTests(unittest.TestCase):
    def test_stats_snapshots_and_web_state_retain_manual_flag(self):
        hop = pmtr.HopStats(2, "192.0.2.2", "known-router", manual=True)
        hop.sent = 1
        hop.record_sent()
        hop.record_reply(12.5)
        hop.history.append((pmtr.time.monotonic(), 12.5))

        snapshots, _, _ = pmtr._snapshot_hops([hop])
        state = json.loads(
            pmtr._build_web_state(
                [hop], "203.0.113.10", pmtr.OutageTracker(), 1, pmtr.time.monotonic()
            )
        )

        self.assertTrue(snapshots[0].manual)
        self.assertEqual(hop.received, 1)
        self.assertEqual(hop.avg_ms, 12.5)
        self.assertTrue(state["hops"][0]["manual"])
        self.assertIn("[M]", state["chart_data"][0]["label"])

    def test_long_chart_label_keeps_manual_marker(self):
        hop = pmtr.HopStats(
            12,
            "192.0.2.2",
            "router-with-an-extremely-long-hostname.example",
            manual=True,
        )

        label = pmtr._hop_chart_label(hop)

        self.assertLessEqual(len(label), 22)
        self.assertTrue(label.endswith(" [M]"))


if __name__ == "__main__":
    unittest.main()
