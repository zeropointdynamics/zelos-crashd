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

import unittest
from os import path

from zelos import Zelos

DATA_DIR = path.join(path.dirname(path.abspath(__file__)), "data")


class TcgTest(unittest.TestCase):
    def test_udchain(self):
        z = Zelos(path.join(DATA_DIR, "test_basic_crash"), taint=True,)

        trace = z.plugins.dataflow.trace

        z.start()
        idx = trace._last_idx_of_address(0x160A)
        ud_chain = z.plugins.dataflow.ud_chain(idx)
        self.assertEqual(ud_chain["rax"][0], 82840)

        idx = trace._last_idx_of_address(0x160A)
        ud_chain = z.plugins.dataflow.ud_chain(idx)
        self.assertEqual(ud_chain["rax"][0], 82840)

        # There was a bug when doing ud_chain twice. Check that
        # computing the ud_chain doesn't change state
        idx = trace._last_idx_of_address(0x160A)
        ud_chain = z.plugins.dataflow.ud_chain(idx)
        self.assertEqual(ud_chain["rax"][0], 82840)

    def test_reverse_taint(self):
        z = Zelos(path.join(DATA_DIR, "test_example_1"), taint=True,)

        z.start()

        taint_graph = z.plugins.dataflow.reverse_taint(0x1606)

        expected_taint_path = {
            # 0x1606: [(0x1606, -1, -1)],
            0x1602: [(0x1606, "rax", "0x0")],
            0x15FE: [(0x1602, 0x7F000008EC50, "0x0")],
            0x1627: [(0x15FE, "rdi", "0x0")],
            0x1623: [(0x1627, "rax", "0x0")],
            0x161F: [(0x1623, 0x7F000008EC78, "0x0")],
            0x161B: [(0x161F, "rax", "0x0")],
            0x1617: [(0x161B, 0x7F000008EC68, "0x0")],
            0x1646: [(0x1617, "rdi", "0x0")],
            0x1642: [(0x1646, "rax", "0x0")],
            0x163A: [(0x1642, 0x7F000008EC98, "0x0")],
        }

        for idx, flow_targets in expected_taint_path.items():
            taint_path = taint_graph._reduced_path
            flow_idx = flow_targets[0][0]
            flow_use = flow_targets[0][1]
            flow_val = flow_targets[0][2]
            self.assertIn(idx, taint_path, msg=f"{idx} {flow_targets}")
            self.assertIn(
                flow_idx, taint_path[idx], msg=f"{idx} {flow_targets}"
            )
            taint_node = taint_path[idx][flow_idx]
            # self.assertEqual(
            #     flow_idx, taint_node.idx, msg=f"{flow_idx} {taint_node}"
            # )
            self.assertEqual(
                flow_use, taint_node.use, msg=f"{flow_use} {taint_node}"
            )
            self.assertEqual(
                flow_val, taint_node.val, msg=f"{flow_val} {taint_node}"
            )


def main():
    unittest.main()


if __name__ == "__main__":
    main()
