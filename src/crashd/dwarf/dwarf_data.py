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

from collections import defaultdict
import os
from pathlib import Path
from typing import Optional

from elftools.dwarf.descriptions import describe_form_class
from elftools.elf.elffile import ELFFile


class AddressEntry:
    def __init__(self, low, high, file, line_num):
        self.low = low
        self.high = high
        self.file = file
        self.line_num = line_num

    def __str__(self):
        return f"(0x{self.low:x}-0x{self.high:x}: {self.file}:{self.line_num})"


class AddressMap:
    def __init__(self):
        self._address_low_high = []
        self._cache = {}
        self._source2addr_range = {}

    def __str__(self):
        return [entry.__str__() for entry in self._address_low_high].__str__()

    def files(self):
        return {entry.file for entry in self._address_low_high}

    def get_addr_range_from_source(self, file, line_num):
        return self._source2addr_range.get(f"{file}{line_num}", (None, None))

    def _add_cache(self, addr, file, line):
        self._cache[addr] = (file, line - 1)

    def add(self, low, high, file, line):
        file = file.decode()
        self._add_cache(low, file, line)
        self._source2addr_range[f"{file}{line}"] = (low, high)
        for addr in range(low, high):
            self._add_cache(addr, file, line)

        entry = AddressEntry(low, high, file, line)
        self._address_low_high.append(entry)
        self._address_low_high.sort(key=lambda x: x.low)

    def get(self, addr: int, default=(None, None)):
        cached_val = self._cache.get(addr, None)
        if cached_val is not None:
            return cached_val

        idx = self.binary_search(addr)
        if idx is not None:
            entry = self._address_low_high[idx]
            retval = (entry.file, entry.line_num - 1)
            self._cache[addr] = retval
            return retval

        return default

    def _attach_src_to_external_addrs(self, trace, dwarf_data):
        """
        Certain addresses in the trace are not associated with source
        code because they are in external modules. We associate those
        addresses with source code from the last line that occurred
        before moving to the external module.
        """
        # External modules can call each other. This means that the same
        # address could have multiple candidates for what address should
        # be associated with them.
        file_lines = dwarf_data._file_lines

        current_source = None
        current_file = None
        current_line = None
        smeared = {}
        for addr in trace:
            file, line_num = self.get(addr)

            if file in file_lines and addr not in smeared:
                dwarf_data._addr2source[addr] = file_lines[file][line_num]
                current_source = file_lines[file][line_num]
                current_file = file
                current_line = line_num
            elif current_source is not None:
                dwarf_data._addr2source[addr] = "within " + current_source
                self._add_cache(addr, current_file, current_line + 1)
                smeared[addr] = current_source

    def binary_search(self, x):
        low = 0
        mid = 0
        high = len(self._address_low_high) - 1
        while low <= high:
            mid = (high + low) // 2
            entry = self._address_low_high[mid]
            if entry.low <= x < entry.high:
                return mid
            if entry.low == entry.high and entry.low == x:
                return mid

            # Check if x is present at mid
            if entry.low < x:
                low = mid + 1

            # If x is greater, ignore left half
            elif entry.low > x:
                high = mid - 1

        # If we reach here, then the element was not present
        return None


class DwarfData:
    """
    Class to parse and hold relevant Dwarf information from binary
    """

    def __init__(self, binary_path, source_path, rebased_module_base=None):
        self._binary_path = binary_path
        self._source_path = source_path
        self._rebased_module_base = rebased_module_base
        self._fp = None
        self._elf = None
        self._dwarfinfo = None
        self._offset = 0
        self._file_lines = {}
        self._file_to_syspath = {}
        self._addr2source = {}
        self._address_map = None
        self._function_map = {}

        self.__load_elf_and_dwarf(binary_path)
        self.__calculate_offset(rebased_module_base)
        self.__set_address_map()
        self.__setup_file_lines()
        self.__build_function_map()

    def __del__(self):
        if hasattr(self._fp, "close"):
            self._fp.close()

    def get_source(self, addr: int) -> Optional[str]:
        return self._addr2source.get(addr, None)

    def get_function_info(self, taint_graph):
        function_map = self._function_map
        addr2func = {}
        for addr in taint_graph._reduced_path.keys():
            for f, ranges in function_map.items():
                for r in ranges:
                    (low, high) = r
                    if low <= addr <= high:
                        addr2func[addr] = f
        return addr2func

    def attach_src_to_external_addrs(self, trace):
        if self._address_map is None:
            return
        self._address_map._attach_src_to_external_addrs(trace, self)

    def __get_elf_module_base(self, elf):
        # This function DOES NOT WORK for static binaries.
        # It gets lucky on binaries where the main module is loaded at 0,
        # which is what this function normally returns. Have to find a way
        # to get the desired load address of binaries. Maybe one way to get
        # around is always return 0 for dynamic binaries.
        segment_addrs = [s.header.p_vaddr for s in elf.iter_segments()]
        # print(f"Segment_addrs: {segment_addrs}")
        return min(segment_addrs)

    def __load_elf_and_dwarf(self, binary_path):
        if os.path.exists(binary_path) and os.path.isfile(binary_path):
            self._fp = open(binary_path, "rb")
            self._elf = ELFFile(self._fp)
            try:
                self._dwarfinfo = self._elf.get_dwarf_info()
                self._elf_module_base = self.__get_elf_module_base(self._elf)
            except:
                pass

    def __calculate_offset(self, rebased_module_base):
        if rebased_module_base is None:
            return
        symbols_module_base = self._elf_module_base
        offset = rebased_module_base - symbols_module_base
        # TODO: TEMP for static binaries
        if offset != 0x10000:
            offset = 0
        # print("Got offset: ", offset)
        self._offset = offset

    def __set_address_map(self):
        if self._dwarfinfo is None:
            return
        dwarfinfo = self._dwarfinfo
        offset = self._offset
        address_map = AddressMap()
        # Go over all the line programs in the DWARF information, looking for
        # one that describes the given address.
        for CU in dwarfinfo.iter_CUs():
            # First, look at line programs to find the file/line for the addr
            lineprog = dwarfinfo.line_program_for_CU(CU)
            prevstate = None
            for entry in lineprog.get_entries():
                # We're interested in entries where a new state is assigned
                if entry.state is None:
                    continue
                if entry.state.end_sequence:
                    # if the line number sequence ends, clear prevstate.
                    prevstate = None
                    continue
                # Looking for a range of addresses in two consecutive states
                # that contain the required address.
                if prevstate:
                    filename = lineprog["file_entry"][prevstate.file - 1].name
                    line = prevstate.line
                    address_map.add(
                        prevstate.address + offset,
                        entry.state.address + offset,
                        filename,
                        line,
                    )
                prevstate = entry.state
        self._address_map = address_map

    def __resolve_filepath(self, path):
        """
        First checks the current directory for the path.
        Then checks recursively in the source code folder for the path
        """
        if os.path.exists(path):
            return path
        matching_files = [path for path in Path(self._source_path).rglob(path)]
        if len(matching_files) == 0:
            # print(
            #     f"Could not find source code file {path} within"
            #     f" {source_code_path}"
            # )
            return None
        if len(matching_files) > 1:
            # print(
            #     f"There is more than one matching file for {path}:"
            #     f" {matching_files}. Picking {matching_files[0]}"
            # )
            pass
        return matching_files[0]

    def __setup_file_lines(self):
        for filename in self._address_map.files():
            resolved_filename = self.__resolve_filepath(filename)
            if resolved_filename is None:
                continue
            f = open(resolved_filename, "r")
            self._file_to_syspath[filename] = resolved_filename
            # Keep this keyed by the original file name so that later on we
            # can find these lines
            self._file_lines[filename] = list(f.readlines())

    def __build_function_map(self):
        """
        Builds the mapping of function names to
        list of tuples: [(low, high), ...]
        """
        dwarfinfo = self._dwarfinfo
        offset = self._offset
        if dwarfinfo is None:
            return
        functions = defaultdict(list)
        entries = []
        for CU in dwarfinfo.iter_CUs():
            for DIE in CU.iter_DIEs():
                die_info = self.__handle_DIE(DIE)
                if die_info is not None:
                    entries.append(die_info)
        for entry in entries:
            func_name = entry["name"]
            low, high = entry["range"]
            functions[func_name].append((low + offset, high + offset))
        self._function_map = functions

    def __handle_DIE(self, DIE):
        def __extract_value(attr, key, default):
            if key in attr.keys():
                return attr[key].value
            return default

        # we are interested in two things: name and address range
        tag = DIE.tag
        attr = DIE.attributes
        # ignore compile unit info
        if tag == "DW_TAG_compile_unit":
            return None
        # check for low_pc
        lowpc = __extract_value(attr, "DW_AT_low_pc", -1)
        # we don't care if DIE holds no address
        if lowpc == -1:
            return None
        elif "DW_AT_high_pc" in attr.keys():
            highpc_attr = attr["DW_AT_high_pc"]
            highpc_attr_class = describe_form_class(highpc_attr.form)
            if highpc_attr_class == "address":
                highpc = highpc_attr.value
            elif highpc_attr_class == "constant":
                highpc = lowpc + highpc_attr.value
        else:
            highpc = lowpc
        # recursive search for name
        current_die = DIE
        while True:
            name = __extract_value(attr, "DW_AT_name", b"")
            if name and current_die.tag == "DW_TAG_subprogram":
                return {"name": name.decode(), "range": (lowpc, highpc)}
            origin = __extract_value(attr, "DW_AT_abstract_origin", -1)
            if origin == -1:
                break
            current_die = current_die.get_DIE_from_attribute(
                "DW_AT_abstract_origin"
            )
            attr = current_die.attributes
        return None
