# Copyright (C) 2020 Zeropoint Dynamics

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.

# You should have received a copy of the GNU Affero General Public
# License along with this program.  If not, see
# <http://www.gnu.org/licenses/>.
# ======================================================================
from __future__ import absolute_import
import unittest
from zelos import Zelos
from os import path
from crashd.asan import AllocInfo, CrashInfo

DATA_DIR = path.join(path.dirname(path.abspath(__file__)), "data")


class AsanTest(unittest.TestCase):
    def test_alloc_record_writes(self):
        alloc_start = 0x42000
        alloc_size = 0x1000
        info = AllocInfo(
            alloc_start, alloc_size, 0x12345, "malloc", is_free=False
        )
        self.assertEqual(0, len(info.get_writes(alloc_start, alloc_size)))
        info._record_write(0x13333, 0x42000, 0x1337)
        self.assertEqual(1, len(info.get_writes(alloc_start, alloc_size)))

    def test_crash_info_exploitability(self):
        expected_exploitability = {
            CrashInfo(reason="double-free", mem_address=0x10000): (
                "EXPLOITABLE"
            ),
            CrashInfo(reason="heap-use-after-free", mem_address=0x10000): (
                "EXPLOITABLE"
            ),
            CrashInfo(
                reason="heap-overflow", operation="WRITE", mem_address=0x10000
            ): (
                "EXPLOITABLE"
            ),
            CrashInfo(
                reason="heap-overflow", operation="READ", mem_address=0x10000
            ): (
                "UNKNOWN"
            ),
        }

        for crash_info, expectation in expected_exploitability.items():
            self.assertEqual(
                crash_info.exploitability,
                expectation,
                f"{crash_info} vs. {expectation}",
            )

    def test_asan_guard_page(self):
        z = Zelos(path.join(DATA_DIR, "test_heap_overflow"), asan=True)
        z.start()

        asan = z.plugins.asan
        self.assertTrue(asan.asan_guard_triggered)
        crash_info = asan._crash_info
        self.assertEqual(crash_info.reason, "heap-overflow")
        self.assertEqual(crash_info.mem_address, 0x90000070)
        self.assertEqual(crash_info.mem_access_size, 8)
        self.assertEqual(crash_info.inst_address, 0x2BE91D)
        self.assertEqual(crash_info.operation, "READ")
        self.assertEqual(crash_info.exploitability, "UNKNOWN")
        alloc_info = crash_info.alloc_info
        self.assertEqual(alloc_info.address, 0x90000050)
        self.assertEqual(alloc_info.size, 0x20)
        self.assertEqual(alloc_info.inst_address, 0x29A070)
        self.assertEqual(alloc_info.is_free, False)

        write_record = alloc_info.writes[0x90000050][0]
        self.assertEqual(write_record.ip_addr, 0x2BE90E)
        self.assertEqual(write_record.value, b"A" * 8)
        self.assertEqual(write_record.mem_addr, 0x90000050)
