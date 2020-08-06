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
from termcolor import colored
import os
import html
from pathlib import Path
from typing import Optional

from elftools.dwarf.descriptions import describe_form_class
from elftools.elf.elffile import ELFFile


def find_file(path, source_code_path):
    """
    First checks the current directory for the path.
    Then checks recursively in the source code folder for the path
    """
    if os.path.exists(path):
        return path
    matching_files = [path for path in Path(source_code_path).rglob(path)]
    if len(matching_files) == 0:
        # print(
        #     f"Could not find source code file {path} within {source_code_path}"
        # )
        return None
    if len(matching_files) > 1:
        # print(
        #     f"There is more than one matching file for {path}: {matching_files}. Picking {matching_files[0]}"
        # )
        pass
    return matching_files[0]


def _construct_zcov_files(
    taint_path, address_map, trace, edges, files, file_to_syspath, src_path
):
    from pathlib import Path
    import json

    crash_line = None
    crash_file = None
    zcov_files = defaultdict(dict)

    # Merge values used for each source code line of dataflow
    for k, v in taint_path.reduced_path.items():
        k_addr = k
        file, line_num = address_map.get(k_addr, (None, None))

        if file not in files:
            continue

        # Get absolute paths, resolve any symbolic links, etc.
        parent_path = os.path.realpath(src_path)
        child_path = os.path.realpath(file_to_syspath[file])

        # Ensure file path is actually rooted in the src parent path
        # (i.e. ignore system libc headers, etc.)
        if os.path.commonpath([parent_path]) != os.path.commonpath(
            [parent_path, child_path]
        ):
            continue

        line_num += 1
        assembly = taint_path._assembly.get(k_addr, "Missing Assembly")
        if crash_line is None:
            kind = "FLOW_END"
            crash_line = line_num
            crash_file = file
            # if taint_path._dataflow.zelos.config.asan:
            #     crash_summary = (
            #         taint_path._dataflow.zelos.plugins.asan.get_crash_summary()
            #     )
            #     crash_summary_comments = "".join(
            #         [f";{line}\n" for line in crash_summary.split("\n")]
            #     )
            #     assembly = crash_summary_comments + assembly
        else:
            kind = "FLOW_THROUGH"
        vals_used = list(set([str(rtd[1].val) for rtd in v.items()]))
        # print(file, line_num, kind, vals_used)
        if int(line_num) in zcov_files[file]:
            existing_vals = zcov_files[file][int(line_num)]["meta"]
            zcov_files[file][int(line_num)]["meta"] = list(
                set(existing_vals + vals_used)
            )
        else:
            zcov_files[file][int(line_num)] = {
                "kind": kind,
                "meta": vals_used,
                "asm": [],
            }
        zcov_files[file][int(line_num)]["asm"].append((k_addr, assembly))

    # print("  zcov merge values")
    # Add lines-executed information
    count = 0
    after_dataflow = True
    addrs = set()
    for addr in reversed(trace):
        file, line_num = address_map.get(addr, (None, None))
        if file not in zcov_files:
            continue
        # Get absolute paths, resolve any symbolic links, etc.
        parent_path = os.path.realpath(src_path)
        child_path = os.path.realpath(file)

        # Ensure file path is actually rooted in the src parent path
        # (i.e. ignore system libc headers, etc.)
        if os.path.commonpath([parent_path]) != os.path.commonpath(
            [parent_path, child_path]
        ):
            continue
        line_num += 1
        if line_num == crash_line:
            after_dataflow = False
        if int(line_num) not in zcov_files[file]:
            if after_dataflow:
                zcov_files[file][int(line_num)] = {
                    "kind": "EXEC_AFTER_FLOW_END",
                    "asm": [],
                }
            else:
                zcov_files[file][int(line_num)] = {"kind": "EXEC", "asm": []}
        if addr in addrs:
            continue
        addrs.add(addr)
        assembly = taint_path._assembly.get(addr, None)
        if assembly is None:
            assembly = taint_path.get_assembly_for_range(addr, addr + 20)[addr]
        zcov_files[file][int(line_num)]["asm"].append((addr, assembly))
        count += 1

    # Add annotation of where asan guarded memory was triggered.
    # if taint_path._dataflow.zelos.plugins.asan._asan_guard_triggered:
    #     addr = (
    #         taint_path._dataflow.zelos.plugins.asan.crash_alloc_info.inst_address
    #     )
    #     file, line_num = address_map.get(addr, (None, None))
    #     line_num += 1
    #     if file in zcov_files:
    #         zcov_files[file][line_num]["kind"] = "ALLOC"

    # print("  zcov added lines executed")
    # Add data flow line edge information
    for src, dests in edges.items():
        srcfile, srcline_num = address_map.get(src, (None, None))
        if srcfile not in zcov_files:
            continue
        srcline_num += 1
        for dest in dests:
            destfile, destline_num = address_map.get(dest, (None, None))
            if destfile not in zcov_files:
                continue
            destline_num += 1

            # print(f"  {destfile}{destline_num} -> {srcfile}{srcline_num}")
            if destfile not in zcov_files or srcfile not in zcov_files:
                continue
            if "data_from" not in zcov_files[destfile][int(destline_num)]:
                zcov_files[destfile][int(destline_num)]["data_from"] = list()
            if "data_to" not in zcov_files[srcfile][int(srcline_num)]:
                zcov_files[srcfile][int(srcline_num)]["data_to"] = list()
            zcov_files[destfile][int(destline_num)]["data_from"].append(
                {"file": srcfile, "line_number": srcline_num}
            )
            zcov_files[srcfile][int(srcline_num)]["data_to"].append(
                {"file": destfile, "line_number": destline_num}
            )
            # print(f"{destfile}{destline_num} -> {srcfile}{srcline_num}")
    # print("  zcov add data flow edges")
    # Generate zcov-formatted JSON
    single_json = {"files": list(), "graphs": list()}
    for file, zcov_content in zcov_files.items():
        if file not in file_to_syspath:
            continue
        zcov_file = Path(file_to_syspath[file]).with_suffix(".zcov")
        zcov_json = defaultdict(dict)
        zcov_json["file"] = file
        lines = []
        for line_num, line_info in zcov_content.items():
            line = {}
            line["line_number"] = line_num
            line["kind"] = line_info["kind"]
            if "data_to" in line_info:
                line["data_from"] = line_info["data_to"]
            if "data_from" in line_info:
                line["data_to"] = line_info["data_from"]
            if "meta" in line_info:
                # Convert vals list to short string
                vals_used = line_info["meta"]
                vals_used = sorted(
                    vals_used, key=lambda x: 0 if "=" in x else 1
                )
                elipsis = ""
                if len(vals_used) > 5:
                    elipsis = f",(+{len(vals_used)-5} more)"
                    vals_used = vals_used[:5]
                info_str = "Vals: " + ",".join(vals_used) + elipsis
                line["meta"] = info_str
            if "asm" in line_info:
                # sorted_lines = sorted(line_info["asm"], key=lambda x: x[0])
                # line["asm"] = [x[1] for x in sorted_lines]
                line["asm"] = [x[1] for x in reversed(line_info["asm"])]
            lines.append(line)
        zcov_json["lines"] = lines
        # json_str = json.dumps(zcov_json, indent=2, sort_keys=True)
        single_json["files"].append(zcov_json)
        # print(f"==== {zcov_file} ====")
        # print(json_str)
        # with open(zcov_file, "w") as f:
        #     f.write(json_str)

    (
        src_graph,
        ordering,
        wave_order,
        child2parents,
        parent2children,
    ) = export_source_graph(taint_path, address_map, files)

    num_waves = max(wave_order.values()) + 1
    wave_ordering = [[] for _ in range(num_waves)]
    for key, wave_num in wave_order.items():
        wave_ordering[wave_num].append(key)

    graph_json = {
        "name": "source_graph",
        "data": src_graph,
        "crashpoint": f"{crash_file}{str(crash_line - 1)}",
        "ordering": ordering,
        "wave_ordering": wave_ordering,
        "child2parents": child2parents,
        "parent2children": parent2children,
    }
    single_json["graphs"].append(graph_json)

    with open(os.path.join(src_path, "crashd.zcov"), "w") as f:
        f.write(json.dumps(single_json, indent=2, sort_keys=True))
    _cwd = os.path.dirname(os.path.realpath(__file__))
    with open(os.path.join(_cwd, "template.html"), "r") as inf:
        with open(os.path.join(src_path, "crashd.graph.html"), "w") as outf:
            data = inf.read()
            data = data.replace(
                "@@ZPD_GRAPH@@", json.dumps(single_json["graphs"])
            )
            outf.write(data)


def annotate_with_dwarf_data(zelos, binary_path, trace, taint_path):
    zelos_module_base = zelos.internal_engine.memory.get_module_base(
        binary_path
    )
    address_map = process_file(binary_path, zelos_module_base)
    dwarf_data = DwarfData(address_map, zelos.config.source_code_path)
    # TODO: The following uses the updated DwarfData
    # dwarf_data = DwarfData(
    #     binary_path, zelos.config.source_code_path, zelos_module_base
    # )
    taint_path._dwarf_data = dwarf_data


def get_nodes_and_edges(taint_graph, address_map):
    # print("Setting up source graph")
    # tuples containing source code addr and next addr to check
    open_paths = [(taint_graph._start_addr, taint_graph._start_addr)]
    # No need to analyze an address that has already been analyzed.
    analyzed_addrs = set()
    # use to defines
    edges = defaultdict(list)
    nodes = set()
    while len(open_paths) > 0:
        child, next_ancestor = open_paths.pop()
        if next_ancestor in analyzed_addrs:
            continue
        analyzed_addrs.add(next_ancestor)
        parents = taint_graph._reduced_path_parents.get(next_ancestor, [])
        for parent in parents:
            if address_map.get(parent, None) is not None:
                edges[child].append(parent)
                nodes.add(child)
                nodes.add(parent)
                if parent not in analyzed_addrs:
                    open_paths.append((parent, parent))
            else:
                if parent not in analyzed_addrs:
                    open_paths.append((child, parent))
    return (nodes, edges)


def show_tainted_source(zelos, binary_path, trace, taint_path):
    dwarf_data = taint_path._dwarf_data
    files = dwarf_data._file_lines
    file_to_syspath = dwarf_data._file_to_syspath
    address_map = dwarf_data._address_map
    address_map._attach_src_to_external_addrs(trace, dwarf_data)

    from crashd.taint.render.graphviz import render_source_graph

    render_source_graph(taint_path, address_map, files)

    (nodes, edges) = get_nodes_and_edges(taint_path, address_map)
    if len(file_to_syspath) > 0:
        _construct_zcov_files(
            taint_path,
            address_map,
            trace,
            edges,
            files,
            file_to_syspath,
            zelos.config.source_code_path,
        )

    if not zelos.config.taint_output == "terminal":
        return

    # print("generated .zcov file")
    crash_line = None
    source_path = {}
    changed_file_lines = defaultdict(list)
    for k, v in taint_path.reduced_path.items():
        k_addr = k
        file, line = address_map.get(k_addr, (None, None))
        source_path[(file, line)] = v
        if file in files:
            if crash_line is None:
                files[file][line] = colored(
                    # f"!0x{k:x}" +
                    files[file][line] + str(v) + "\n",
                    color="red",
                )
                crash_line = line
                changed_file_lines[file].append(line)
            else:
                files[file][line] = colored(
                    # f"*0x{k:x}" +
                    files[file][line] + str(v) + "\n",
                    color="white",
                    attrs=["bold"],
                )
                changed_file_lines[file].append(line)

    # print("Updated source lines with data flow")
    count = 0
    # Get first trace line that is in the source
    for addr in reversed(trace):
        file, line = address_map.get(addr, (None, None))
        if file not in files:
            continue
        if line == crash_line:
            break
        files[file][line] = colored(
            files[file][line] + f" Count: {count}\n",
            color="green",
            attrs=["bold"],
        )
        changed_file_lines[file].append(line)
        count += 1

    # print("Updated source lines with trace to crash")

    if len(changed_file_lines) == 0:
        print(
            "There are no lines in source that correspond to the taint path."
            " There may have been a bug."
        )

    for path, lines in files.items():
        if path not in changed_file_lines:
            continue
        idxes = changed_file_lines[path]
        # print(path, idxes)
        lines_to_print = []
        indices_chosen = set()
        context = 3
        for idx in reversed(idxes):
            i = idx - context
            while i < idx + context + 1:
                if i < 0 or i >= len(lines):
                    i += 1
                    continue
                if i in indices_chosen:
                    i += 1
                    continue
                if i > idx and i in idxes:
                    idx = i
                lines_to_print.append(lines[i])
                indices_chosen.add(i)
                i += 1
            if lines_to_print[-1] != "...\n":
                lines_to_print.append("...\n")
        print("".join(lines_to_print))

    # print("Changed lines: ")
    # print(changed_file_lines)
    # print("Num lines: ", len(changed_file_lines))


def process_file(filename, zelos_module_base):
    """
    Returns a dictionary containing addr -> (file, 0-indexed source code line)
    Returns 0 indexed results, while ElfFile gives 1 indexed results
    """
    # print("Processing file:", filename)
    with open(filename, "rb") as f:
        elffile = ELFFile(f)
        if not elffile.has_dwarf_info():
            # print("  file has no DWARF info")
            return

        symbols_module_base = _get_module_base(elffile)
        offset = zelos_module_base - symbols_module_base
        if offset != 0x1000:  # TODO TEMP for static binaries
            offset = 0
        # print("Got offset: ", offset)
        total_address_map = {}
        dwarfinfo = elffile.get_dwarf_info()

        return decode_file_lines(dwarfinfo, offset)


def __extract_value(attr, key, default):
    if key in attr.keys():
        return attr[key].value
    return default


def __handle_DIE(DIE):
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


def get_function_info(filename, taint_graph, zelos_module_base):
    """
    Returns mapping of function names to tuple (low addr, high addr)
    """
    # print("Parsing DWARF info")
    with open(filename, "rb") as f:
        elffile = ELFFile(f)
        if not elffile.has_dwarf_info():
            # print("  file has no DWARF info")
            return

        symbols_module_base = _get_module_base(elffile)
        offset = zelos_module_base - symbols_module_base
        if offset != 0x1000:  # TODO TEMP for static binaries
            offset = 0
        # print("Got offset: ", offset)
        dwarfinfo = elffile.get_dwarf_info()
        functions = defaultdict(list)
        entries = []
        for CU in dwarfinfo.iter_CUs():
            for DIE in CU.iter_DIEs():
                die_info = __handle_DIE(DIE)
                if die_info is not None:
                    entries.append(die_info)
        for entry in entries:
            func_name = entry["name"]
            low, high = entry["range"]
            functions[func_name].append((low + offset, high + offset))
    # print("  Constructing addr2func")
    addr2func = {}
    for addr in taint_graph._reduced_path.keys():
        for f, ranges in functions.items():
            for r in ranges:
                (low, high) = r
                if low <= addr <= high:
                    addr2func[addr] = f
    # print("Done parsing dwarf info")
    return addr2func


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
        files = dwarf_data._file_lines

        current_source = None
        current_file = None
        current_line = None
        smeared = {}
        for addr in trace:
            file, line_num = self.get(addr)

            if file in files and addr not in smeared:
                dwarf_data._addr2source[addr] = files[file][line_num]
                current_source = files[file][line_num]
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
    def __init__(self, address_map, source_code_path):
        self._address_map = address_map
        self._file_lines = {}
        self._file_to_syspath = {}
        self._addr2source = {}

        self.setup_file_lines(source_code_path)

    def setup_file_lines(self, source_code_path):
        for filename in self._address_map.files():
            located_filename = find_file(filename, source_code_path)
            if located_filename is None:
                continue
            f = open(located_filename, "r")
            self._file_to_syspath[filename] = located_filename
            # Keep this keyed by the original file name so that later on we
            # can find these lines
            self._file_lines[filename] = list(f.readlines())

    def get_source(self, addr: int) -> Optional[str]:
        return self._addr2source.get(addr, None)


def decode_file_lines(dwarfinfo, offset):
    address_map = AddressMap()
    # Go over all the line programs in the DWARF information, looking for
    # one that describes the given address.
    for CU in dwarfinfo.iter_CUs():
        # First, look at line programs to find the file/line for the address
        lineprog = dwarfinfo.line_program_for_CU(CU)
        prevstate = None
        for entry in lineprog.get_entries():
            # We're interested in those entries where a new state is assigned
            if entry.state is None:
                continue
            if entry.state.end_sequence:
                # if the line number sequence ends, clear prevstate.
                prevstate = None
                continue
            # Looking for a range of addresses in two consecutive states that
            # contain the required address.
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
    return address_map


def _get_module_base(elf_file):
    # This function DOES NOT WORK for static binaries.
    # It gets lucky on binaries where the main module is loaded at 0,
    # which is what this function normally returns. Have to find a way
    # to get the desired load address of binaries. Maybe one way to get
    # around is always return 0 for dynamic binaries.
    segment_addrs = [s.header.p_vaddr for s in elf_file.iter_segments()]
    # print(f"Segment_addrs: {segment_addrs}")
    return min(segment_addrs)


# ELK Graph Functions


def _calc_width(text):
    return len(text) * 8 + 20


def _create_node(_file, _line, _text):
    _id = f"{_file}{_line}"
    node = {
        "id": _id,
        "labels": [{"id": f"{_id}_label", "text": _text, "x": 10, "y": 4,}],
        "width": _calc_width(_text),
        "height": 24,
        "file": f"{_file}",
        "line": _line,
    }
    return node


def _create_group(_id, label=None):
    group = {
        "id": f"group_{_id}",
        "children": [],
        "edges": [],
        "layoutOptions": {"elk.direction": "DOWN"},
    }
    if label:
        group["labels"] = [
            {
                "id": f"group_{_id}_label",
                "text": f"{html.escape(label)}",
                "width": _calc_width(label),
                "height": 24,
            }
        ]
    return group


def _create_edge(srcfile, srcline, destfile, destline):
    _src = f"{srcfile}{srcline}"
    _dest = f"{destfile}{destline}"
    _id = f"edge_{_src}{_dest}"
    edge = {
        "id": _id,
        "source": _dest,
        "target": _src,
        "sourceFile": destfile,
        "targetFile": srcfile,
        "sourceLine": destline,
        "targetLine": srcline,
    }
    return edge


def _find_group(edge, groups):
    # Given an edge, search for a function-group
    # that contains both it's source and target
    # nodes.
    src_group = None
    dest_group = None
    for fn, g in groups.items():
        for c in g.get("children", []):
            if edge["sourceFile"] == c.get("file", None) and edge[
                "sourceLine"
            ] == c.get("line", None):
                src_group = fn
            if edge["targetFile"] == c.get("file", None) and edge[
                "targetLine"
            ] == c.get("line", None):
                dest_group = fn
            if src_group is not None and dest_group is not None:
                if src_group == dest_group:
                    return src_group
                return None
    return None


def _find_fn(file, line, groups):
    # Given a file and line number, search for
    # it's containing function-group
    for fn, g in groups.items():
        for c in g.get("children", []):
            if file == c.get("file", None) and line == c.get("line", None):
                return fn
    return None


def _find_edges(node, groups):
    # Given a node that is not part of a group,
    # search for a function-group that contains
    # edges to or from it.
    for fn, g in groups.items():
        for e in g.get("edges", []):
            if (
                node["file"] == e["sourceFile"]
                or node["file"] == e["targetFile"]
            ) and (
                node["line"] == e["sourceLine"]
                or node["line"] == e["targetLine"]
            ):
                return fn
    return None


def export_source_graph(taint_path, address_map, files):
    # Helper function for getting id for the source graph
    def get_node_id(address_map, addr):
        (file, line_num) = address_map.get(addr, (None, None))
        if file is None:
            return None
        return f"{file}{line_num}"

    graph_boy = {
        "id": "root",
        "layoutOptions": {
            "algorithm": "layered",
            "elk.direction": "DOWN",
            "hierarchyHandling": "INCLUDE_CHILDREN",
        },
        "children": [],
        "edges": [],
    }
    # tuples containing source code addr and next addr to check
    open_paths = [(taint_path._start_addr, taint_path._start_addr)]
    # No need to analyze an address that has already been analyzed.
    analyzed_addrs = set()
    # use to defines
    edges = defaultdict(list)
    nodes = set()
    # The order of nodes
    ordering = []
    # Wave order is broken if you do analysis in depth first search.
    # The algorithm for calculating wave order only works if you use
    # breadth first.
    wave_order = {get_node_id(address_map, taint_path._start_addr): 0}
    child2parents = defaultdict(list)
    parent2children = defaultdict(list)
    while len(open_paths) > 0:
        child, next_ancestor = open_paths.pop()
        if next_ancestor in analyzed_addrs:
            continue
        if child not in taint_path._addr2func:
            if taint_path._dataflow.zelos.config.link_ida is not None:
                taint_path._addr2func[
                    child
                ] = taint_path._dataflow._get_ida_func_name(child)

        analyzed_addrs.add(next_ancestor)

        ancestor_id = get_node_id(address_map, next_ancestor)
        if ancestor_id not in ordering:
            ordering.append(ancestor_id)

        parents = taint_path._reduced_path_parents.get(next_ancestor, [])
        for parent in parents:
            (file, line_num) = address_map.get(parent, (None, None))
            if file is None:
                if parent not in analyzed_addrs:
                    open_paths.append((child, parent))
                continue

            edges[child].append(parent)
            nodes.add(child)
            nodes.add(parent)
            child_id = get_node_id(address_map, child)
            parent_id = get_node_id(address_map, parent)
            if parent_id not in wave_order:
                wave_order[parent_id] = wave_order[child_id] + 1
            if parent not in analyzed_addrs:
                open_paths.append((parent, parent))

    groups = dict()
    added_nodes = set()
    function_map = taint_path._addr2func
    line2func = defaultdict(lambda: defaultdict(None))
    for n in nodes:
        file, line_num = address_map.get(n, (None, None))
        if file not in files:
            continue
        function = function_map.get(n, None)
        if function is not None:
            if function and function not in groups.keys():
                fn_label = f"{file}::{function}"
                groups[function] = _create_group(function, label=fn_label)
            if file and line_num:
                line2func[file][line_num] = function

        src_line = files[file][line_num].strip()
        fline = f"{file}{line_num}"
        if fline in added_nodes:
            continue
        added_nodes.add(fline)
        # add node
        node = _create_node(file, line_num, " ".join(src_line.split()))
        if function:
            groups[function]["children"].append(node)
        else:
            graph_boy["children"].append(node)

    added_edges = set()
    for src, dests in edges.items():
        srcfile, srcline_num = address_map.get(src, (None, None))
        srcfn = function_map.get(src, None)
        if srcfn is None:
            srcfn = line2func[srcfile].get(srcline_num, None)
        for dest in dests:
            destfile, destline_num = address_map.get(dest, (None, None))
            destfn = function_map.get(dest, None)
            if destfn is None:
                destfn = line2func[destfile].get(destline_num, None)
            src = f"{srcfile}{srcline_num}"
            dest = f"{destfile}{destline_num}"
            if src == "NoneNone" or dest == "NoneNone":
                continue
            edge_name = f"edge_{src}{dest}"
            if edge_name in added_edges:
                continue
            if src not in added_nodes or dest not in added_nodes:
                continue

            child2parents[src].append((edge_name, dest))
            parent2children[dest].append((edge_name, src))

            added_edges.add(edge_name)
            edge = _create_edge(srcfile, srcline_num, destfile, destline_num)
            fn = _find_group(edge, groups)
            if fn is not None:
                groups[fn]["edges"].append(edge)
            # Same function
            elif srcfn and srcfn == destfn:
                groups[srcfn]["edges"].append(edge)
            # Different function
            elif srcfn and destfn and srcfn != destfn:
                graph_boy["edges"].append(edge)
            # could be either
            else:
                # if a sourcefile is known and the same
                if (srcfile or destfile) and srcfile == destfile:
                    # if the line number same
                    if (
                        srcline_num or destline_num
                    ) and srcline_num == destline_num:
                        # If line num same and one is mapped to a fn
                        # it's safe to assume same fn
                        if srcfn is not None and destfn is None:
                            groups[srcfn]["edges"].append(edge)
                        elif srcfn is None and destfn is not None:
                            groups[destfn]["edges"].append(edge)
                        else:
                            # If line num is same but neither mapped to a fn
                            # Check if we've seen this address mapped to a fn
                            # previously.
                            fn = _find_fn(srcfile, srcline_num, groups)
                            if fn is not None:
                                groups[fn]["edges"].append(edge)
                            else:
                                graph_boy["edges"].append(edge)
                    else:
                        # if different line number, check that we've seen both previously
                        sfn = _find_fn(srcfile, srcline_num, groups)
                        dfn = _find_fn(destfile, destline_num, groups)
                        if (sfn or dfn) and sfn == dfn:
                            groups[sfn]["edges"].append(edge)
                        else:
                            graph_boy["edges"].append(edge)
                else:
                    graph_boy["edges"].append(edge)

    # Take care of any incorrect func mappings
    tmp = []
    for c in graph_boy["children"]:
        if c.get("file", None) and c.get("line", None):
            fn = _find_edges(c, groups)
            if fn is not None:
                groups[fn]["children"].append(c)
            else:
                tmp.append(c)
    graph_boy["children"] = tmp

    # Take care of any incorrect edges
    tmp = []
    for e in graph_boy["edges"]:
        fn = _find_group(e, groups)
        if fn is not None:
            groups[fn]["edges"].append(e)
        else:
            tmp.append(e)
    graph_boy["edges"] = tmp

    for fn in groups.keys():
        graph_boy["children"].append(groups[fn])

    # import json
    # with open("output.json", "w") as fp:
    #     json.dump(graph_boy, fp)
    return graph_boy, ordering, wave_order, child2parents, parent2children
