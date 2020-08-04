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

from zelos.exceptions import MemoryReadUnmapped
from typing import List, Dict
from collections import defaultdict

import math
import re


class TaintNode:
    """
    TODO
    """

    def __init__(self, taint_graph, idx, use, val):
        self.idx = idx
        self.use = use
        self.val = val
        self._taint_graph = taint_graph
        try:
            potential_addr = int(val, 0)
            self._taint_graph._dataflow.zelos.memory.read_int(potential_addr)
            self.val = "*" + self.val
        except Exception:
            # Not a valid memory address
            pass

    def addr(self) -> int:
        return self._taint_graph._dataflow.trace._trace[self.idx]

    def use_string(self) -> str:
        if isinstance(self.use, int):
            return f"Use: 0x{self.use:x} Value: {self.val}"
        else:
            return f"Use: {self.use} Value: {self.val}"

    def __str__(self):
        return f"(Addr: 0x{self.addr():x} {self.use_string()})"

    def __repr__(self):
        return self.__str__()


class ReducedTaintNode:
    """
    TODO
    """

    def __init__(self, taint_graph, taint_node):
        self._taint_graph = taint_graph
        self._taint_nodes = [taint_node]

    @property
    def idx(self):
        return self._taint_nodes[0].idx

    @property
    def use(self):
        return self._taint_nodes[0].use

    @property
    def val(self):
        return self._taint_nodes[0].val

    def addr(self) -> int:
        return self._taint_graph._dataflow.trace._trace[self.idx]

    def use_string(self) -> str:
        if isinstance(self.use, int):
            return (
                f"Use: 0x{self.use:x} Value: {self.val} Iter:"
                f" {len(self._taint_nodes)}"
            )
        else:
            return (
                f"Use: {self.use} Value: {self.val} Iter:"
                f" {len(self._taint_nodes)}"
            )

    def add_node(self, taint_node):
        self._taint_nodes.append(taint_node)

    def __str__(self):
        return f"(Addr: 0x{self.addr():x} {self.use_string()})"

    def __repr__(self):
        return self.__str__()


class TaintGraph:
    """
    TODO
    """

    def __init__(self, dataflow, start_addr, crashing_address=None):
        self.logger = dataflow.logger
        self._dataflow = dataflow

        "Keys are the index in the trace"
        self._path: Dict[int, Dict[int, TaintNode]] = defaultdict(dict)

        self._path_parents = defaultdict(list)

        """Keys are the address. This is an optimization to
        reduce the size of the graph."""
        self._reduced_path: Dict[
            int, Dict[int, ReducedTaintNode]
        ] = defaultdict(dict)

        self._reduced_path_parents = defaultdict(set)
        self._start_addr = start_addr
        self._assembly = defaultdict(str)
        self._addr2func = {}

        self._dwarf_data = None
        self.reverse_taint(start_addr, crashing_address)

    def __str__(self):
        s = ""
        count = 100
        if len(self._reduced_path) > 0:
            for addr, defines in self._reduced_path.items():
                s += f"0x{addr:x} {defines}\n"
                s += f"  assembly: {self._assembly[addr]}\n"
                funcname = self._addr2func.get(addr, None)
                if funcname is not None:
                    s += f"  func: {funcname}\n"
                srccode = self.get_source(addr)
                if srccode is not None:
                    s += f"  src: {srccode}\n"
                count -= 1
                if count == 0:
                    break
            return s

        for idx, defines in self._path.items():
            addr = self._dataflow.trace._trace[idx]
            s += f"0x{addr:x} {defines}\n"
        return s

    @property
    def reduced_path(self):
        return self._reduced_path

    def get_source(self, addr: int):
        if self._dwarf_data is None:
            return None
        return self._dwarf_data.get_source(addr)

    def get_assembly_from_source(self, file, line_num):
        address_map = self._dwarf_data._address_map
        (addr_low, addr_high) = address_map.get_addr_range_from_source(
            file, line_num
        )
        if addr_low is None or addr_high is None:
            return None
        return self.get_assembly_for_range(addr_low, addr_high)

    def _reduce(self):
        """
        Creates the reduced path which ensures that uses the address as
        the key instead of the index
        """
        if len(self._reduced_path) > 0:
            return  # Already reduced
        for idx, taint_nodes in self._path.items():
            addr = self._dataflow.trace._trace[idx]
            for taint_node in taint_nodes.values():
                node_addr = self._dataflow.trace._trace[taint_node.idx]
                if node_addr in self._reduced_path[addr]:
                    self._reduced_path[addr][node_addr].add_node(taint_node)
                else:
                    self._reduced_path[addr][node_addr] = ReducedTaintNode(
                        self, taint_node
                    )
                self._reduced_path_parents[node_addr].add(addr)

            # Add information about the assembly instructions
            if addr not in self._assembly:
                inst_strings = self.get_assembly_for_range(addr, addr + 20)
                self._assembly[addr] = inst_strings[addr]

        # Filter out adjacent push-pop pairs
        for addr, taint_nodes in list(self._reduced_path.items()):
            if " push " not in self._assembly.get(addr, ""):
                continue
            if len(taint_nodes) != 1:
                continue
            child_addr = list(taint_nodes.keys())[0]
            node = taint_nodes[child_addr]
            if " pop " not in self._assembly[child_addr]:
                continue
            grand_children = {
                k: v
                for k, v in self._reduced_path[child_addr].items()
                if "push" not in self._assembly[k]
            }
            grand_parents = [
                x
                for x in self._reduced_path_parents[addr]
                if "pop" not in self._assembly[x]
            ]
            # print("Beginning Deletion")
            # for gp in grand_parents:
            #     print(f"  grand parent 0x{gp:x} {self._assembly[gp]}")
            #     print(f"    children: {self._reduced_path[gp]}")
            # print(f"  parent: {addr:x} {self._assembly[addr]}")
            # print(f"  child: {child_addr:x} {self._assembly[child_addr]}")
            # for gc_addr in grand_children.keys():
            #     print(
            #         f"  grand_children {gc_addr:x} {self._assembly[gc_addr]}"
            #     )

            for gp in grand_parents:
                del self._reduced_path[gp][addr]
            del self._reduced_path[addr]
            del self._reduced_path[child_addr]
            del self._reduced_path_parents[addr]
            del self._reduced_path_parents[child_addr]

            # print(
            #     f"  Deleted push-pop pair {self._assembly[addr]} and {self._assembly[child_addr]}"
            # )

            for grand_child_addr, grand_child in grand_children.items():
                # print(f"  adding grand child 0x{grand_child_addr:x}")
                self._reduced_path_parents[grand_child_addr].remove(child_addr)
                self._reduced_path_parents[grand_child_addr].update(
                    grand_parents
                )
                for gp in grand_parents:
                    self._reduced_path[gp][grand_child_addr] = grand_child

            # print("After:")

            # for gp in grand_parents:
            #     print(" ", [hex(k) for k in self._reduced_path[gp].keys()])
            # for gc in grand_children.keys():
            #     print(f" Grand child {gc:x}",)
            #     print(
            #         f"    grand parents: {[hex(x) for x in self._reduced_path_parents[gc]]}"
            #     )

    def get_assembly_for_range(self, addr_low, addr_high):
        try:
            code = self._dataflow.memory.read(addr_low, addr_high - addr_low)
        except MemoryReadUnmapped:
            print(f"Error trying to read 0x{addr_low:x}-0x{addr_high:x}")
            return {}
        if self._dataflow.zelos.config.link_ida is not None:
            try:
                ida_disasm = self._dataflow.zelos.plugins.ida.idc.GetDisasm(
                    addr_low
                )
                if ida_disasm is not None and ida_disasm != "":
                    self._annotate_variables_in_path(addr_low, ida_disasm)
                    return {
                        addr_low: (
                            f"0x{addr_low:x}: {ida_disasm} ;"
                            f" {self._dataflow.trace._addr_comment.get(addr_low, '')}"
                        )
                    }
            except Exception as e:
                print("Ida address exception: ", e)
                # raise e
                pass
        inst_list = list(
            self._dataflow.zelos.internal_engine.cs.disasm(code, addr_low)
        )
        return {
            i.address: (
                f"0x{i.address:x}: {i.mnemonic} {i.op_str} ;"
                f" {self._dataflow.trace._addr_comment.get(i.address, '')}"
            )
            for i in inst_list
        }

    def _annotate_variables_in_path(self, addr: int, ida_disasm: str):
        if ida_disasm is None:
            return
        if "mov" not in ida_disasm and "lea" not in ida_disasm:
            return

        cmd, args = ida_disasm.split(maxsplit=1)
        if cmd not in ["mov", "lea"]:
            return
        dest, src = args.split(",", maxsplit=1)
        var_name = None
        if "[" in dest and "[" not in src:
            var_name = self._get_ida_variable(dest)
        if "[" in src and "[" not in dest:
            var_name = self._get_ida_variable(src)
        if var_name is None:
            return
        if cmd == "lea":
            var_name = "&" + var_name
        for reduced_nodes in self._reduced_path[addr].values():
            for node in reduced_nodes._taint_nodes:
                node.val = f"{var_name}={node.val}"

    def _get_ida_variable(self, s):
        """
        Get the variable name from Ida disassembly if it exists.
        """
        match = re.search(r"\[.bp\+(\w+)\]", s)
        if match is not None:
            return match.group(1)
        match = re.search(
            r"\[.sp\+[0-9A-Fa-f]+h\+([A-Za-z][A-Za-z0-9.]*)\]", s
        )
        if match is None:
            return None
        return match.group(1)

    def reverse_taint(self, start_addr: int, crashing_addr: int):
        """
        Returns a list of addresses.
        Each address also contains what address tainted them and why.
        """

        start_idx = self._dataflow.trace._last_idx_of_address(start_addr)
        self._path[start_idx][-1] = TaintNode(self, -1, -1, -1)
        indices_to_analyze = []
        has_been_analyzed = set()

        self._add_uses(
            start_idx, indices_to_analyze, restrict_to_value=crashing_addr
        )

        while len(indices_to_analyze) > 0:
            current_idx = indices_to_analyze.pop()

            # Print how long the path on occasion
            self._maybe_log(current_idx, indices_to_analyze)
            self._add_uses(current_idx, indices_to_analyze)

        self._reduce()

    def _add_uses(
        self,
        current_idx: int,
        indices_to_analyze: List[int],
        restrict_to_value=None,
    ):
        reg_uses = self._dataflow.ud_chain(current_idx)
        for use, define_idxs in reg_uses.items():
            if use in [
                "ebp",
                "esp",
                "rbp",
                "rsp",
                "cc_src",
                "cc_src2",
                "cc_dst",
                "cc_op",
                "eq",
                "ne",
                "ltu",
                "leu",
                "gtu",
                "geu",
            ]:
                continue
            for define_idx in define_idxs:
                defines = self._dataflow.trace.get_defines(define_idx)
                val = defines[use]
                if (
                    restrict_to_value is not None
                    and hex(restrict_to_value) != val
                ):
                    continue
                if define_idx not in self._path:
                    indices_to_analyze.append(define_idx)
                self.create_taint_node(
                    define_idx, current_idx, use, val,
                )

        mem_uses = self._dataflow.trace.get_uses(current_idx)
        for use, define_idx in mem_uses.items():
            if define_idx is None:
                inst_addr = self._dataflow.trace._trace[current_idx]
                self.logger.warning(
                    "Memory use has not been defined "
                    f"inst addr: {inst_addr:x} mem_addr: {use:x}"
                )
                continue
            defines = self._dataflow.trace.get_defines(define_idx)
            val = defines[use]
            if restrict_to_value is not None and hex(restrict_to_value) != val:
                continue
            if define_idx not in self._path:
                indices_to_analyze.append(define_idx)
            self.create_taint_node(
                define_idx, current_idx, use, val,
            )

    def _maybe_log(self, current_idx: int, indices_to_analyze: List[int]):
        path_len = len(self._path)
        order_of_magnitude = 10 ** math.floor(math.log10(path_len))
        if path_len % max(100, order_of_magnitude) == 0:
            self.logger.info(
                f"Path size: {path_len}, Analyzing idx {current_idx}"
                f" left:{len(indices_to_analyze)}"
            )

    def create_taint_node(self, define_idx, current_idx, use, val):
        self._path[define_idx][current_idx] = TaintNode(
            self, current_idx, use, val
        )
        self._path_parents[current_idx].append(define_idx)

    def _addr_label(self, key: int):
        if len(self._reduced_path) > 0:
            address = key
        else:
            address = self._dataflow.trace._trace[key]

        if self._dataflow.zelos.config.link_ida is not None:
            name = self._dataflow._get_ida_func_name(address)
            func_addr = self._dataflow.names.get(name, None)
        else:
            func_addr = None

        s = self._assembly[address]

        region = self._dataflow.zelos.memory.get_region(address)

        label_override = self._dataflow.trace.label_overrides.get(
            address, None
        )
        if label_override is not None:
            label = label_override
        elif func_addr is None:
            label = f"0x{address:x} {region.name} {region.module_name}"
        else:
            label = f"{name}+0x{address-func_addr:x}"
        s = f"{label}\n{s}\n"
        source_code = self.get_source(address)
        if source_code is not None:
            s += source_code + "\n"
        return s
