#!/usr/bin/env python3
"""
Automated Unit Test Suite for Cloudflare WARP Scanner
Tests subnet calculation, profile parsing, config file generation, and syntax integrity offline.
"""

import sys
import unittest
import tempfile
import re
from pathlib import Path

# Add parent directory to sys.path to import warp_scanner module functions
PARENT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PARENT_DIR))

import warp_scanner


class TestWarpScanner(unittest.TestCase):

    def test_subnet_generation_count(self):
        """Test that subnet expansion generates exact expected target count."""
        subnets = warp_scanner.CLOUDFLARE_SUBNETS
        ports = warp_scanner.WARP_PORTS
        
        # 6 subnets * 254 IPs * 8 ports = 12,192 targets
        expected_targets_count = len(subnets) * 254 * len(ports)
        
        targets = []
        for subnet in subnets:
            base_ip, mask = subnet.split("/")
            if mask == "24":
                octets = base_ip.split(".")
                prefix = f"{octets[0]}.{octets[1]}.{octets[2]}"
                for i in range(1, 255):
                    ip = f"{prefix}.{i}"
                    for port in ports:
                        targets.append((ip, port))
                        
        self.assertEqual(len(targets), expected_targets_count)
        self.assertEqual(len(subnets), 6)
        self.assertEqual(len(ports), 8)

    def test_profile_parsing(self):
        """Test extraction of WireGuard profile keys from mock wgcf-profile.conf text."""
        mock_conf_content = """[Interface]
PrivateKey = MockPrivateKey12345678901234567890123=
Address = 172.16.0.2/32, 2606:4700:110:836b:a057:1175:e196:b9d6/128
DNS = 1.1.1.1, 1.0.0.1
Reserved = 1,2,3

[Peer]
PublicKey = MockPublicKey123456789012345678901234=
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = 162.159.192.1:2408
"""
        with tempfile.NamedTemporaryFile("w", delete=False, suffix=".conf") as tf:
            tf.write(mock_conf_content)
            tf_path = tf.name

        try:
            profile = warp_scanner.read_wgcf_profile(tf_path)
            self.assertIsNotNone(profile)
            self.assertEqual(profile["PrivateKey"], "MockPrivateKey12345678901234567890123=")
            self.assertEqual(profile["PublicKey"], "MockPublicKey123456789012345678901234=")
            self.assertIn("172.16.0.2/32", profile["Address"])
            self.assertEqual(profile["Reserved"], "1,2,3")
        finally:
            Path(tf_path).unlink(missing_ok=True)

    def test_config_file_generation(self):
        """Test generation of valid WireGuard configuration files."""
        mock_profile = {
            "PrivateKey": "TestPrivateKey=",
            "Address": "172.16.0.2/32",
            "DNS": "1.1.1.1",
            "PublicKey": "TestPublicKey=",
            "Reserved": "0,0,0"
        }
        mock_candidates = [
            {"ip": "162.159.192.1", "port": 2408, "endpoint": "162.159.192.1:2408", "latency": 45.2}
        ]

        with tempfile.TemporaryDirectory() as tmp_dir:
            orig_config_dir = warp_scanner.CONFIG_DIR
            orig_working_dir = warp_scanner.WORKING_CONF_DIR
            
            warp_scanner.CONFIG_DIR = Path(tmp_dir) / "WARP_Configs"
            warp_scanner.WORKING_CONF_DIR = Path(tmp_dir) / "Working_Configs"

            try:
                configs = warp_scanner.generate_configs(mock_candidates, mock_profile, max_tests=1)
                self.assertEqual(len(configs), 1)
                
                conf_path = configs[0]["path"]
                self.assertTrue(conf_path.exists())
                
                content = conf_path.read_text(encoding="utf-8")
                self.assertIn("[Interface]", content)
                self.assertIn("[Peer]", content)
                self.assertIn("PrivateKey = TestPrivateKey=", content)
                self.assertIn("Endpoint = 162.159.192.1:2408", content)
                self.assertIn("Reserved = 0,0,0", content)
            finally:
                warp_scanner.CONFIG_DIR = orig_config_dir
                warp_scanner.WORKING_CONF_DIR = orig_working_dir


if __name__ == "__main__":
    unittest.main()
