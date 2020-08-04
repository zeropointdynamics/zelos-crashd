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
from crashd.dwarf import DwarfData

DATA_DIR = path.join(path.dirname(path.abspath(__file__)), "data")


class DwarfDataTest(unittest.TestCase):
    def test_default_offset(self):
        srcpath = DATA_DIR
        binpath = path.join(DATA_DIR, "test_dwarf_data")

        dwarfdata = DwarfData(binpath, srcpath)
        self.assertEqual(dwarfdata._offset, 0)

        class TestTaintGraph:
            def __init__(self):
                self._reduced_path = {1653: 0, 1710: 1, 9999: 2}

        taint_graph = TestTaintGraph()
        function_info = dwarfdata.get_function_info(taint_graph)
        self.assertIsInstance(function_info, dict)
        self.assertIn(1653, function_info.keys())
        self.assertIn(1710, function_info.keys())
        self.assertNotIn(9999, function_info.keys())

        self.assertEqual(function_info[1653], "factorial")
        self.assertEqual(function_info[1710], "main")

    def test_offset(self):
        srcpath = DATA_DIR
        binpath = path.join(DATA_DIR, "test_dwarf_data")

        dwarfdata = DwarfData(binpath, srcpath, 0x1337)
        self.assertEqual(dwarfdata._rebased_module_base, 0x1337)
        self.assertEqual(
            dwarfdata._rebased_module_base - dwarfdata._elf_module_base, 0x1337
        )
        # TODO: DwarfData._offset is currently always 0, unless
        #       DwarfData._rebased_module_base - DwarfData._elf_module_base
        #       == 0x10000
        #       Appears to be a temporary hack for static binaries.
        self.assertEqual(dwarfdata._offset, 0)


def main():
    unittest.main()


if __name__ == "__main__":
    main()
