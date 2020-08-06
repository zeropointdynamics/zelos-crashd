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

from zelos import Zelos, HookType, IPlugin, CommandLineOption
from zelos.exceptions import InvalidRegException
from typing import List, Dict, Union
from collections import defaultdict

import functools
import os

from crashd.taint.tcg import TCGParse
from crashd.taint.taint_graph import TaintGraph
from crashd.dwarf.dwarf_source_code import (
    show_tainted_source,
    annotate_with_dwarf_data,
    get_function_info,
)

from zelos.ext.plugins.trace import Trace

_ = Trace

CommandLineOption(
    "taint",
    action="store_true",
    help=(
        "Enables collection of data that allows for taint tracking."
        " Collection will slow down overall run."
    ),
)

CommandLineOption(
    "taint_when",
    action="append",
    nargs="?",
    default=[],
    const="",
    metavar="ZML_STRING",
    help="Starts taint tracking when the specified ZML condition is met.",
)

CommandLineOption(
    "taint_output", default="", help="Specify taint output location.",
)

CommandLineOption(
    "source_code_path", default="", help="path to search for source code files"
)


class DataFlowException(Exception):
    pass


class TraceInfo:
    def __init__(self):
        self._trace: List[int] = []
        self._addr_comment: Dict[int, str] = {}
        """Map of idx to {memory_addr|reg: last_define_idx}"""
        self.uses = defaultdict(dict)
        """Map of idx -> {memory_addr|reg: value}"""
        self.defines = defaultdict(dict)

        """ Map of memory_addr|reg to last write idx"""
        self.last_write = {}
        self.label_overrides = {}

    @property
    def current_idx(self) -> int:
        return len(self._trace) - 1

    @property
    def last_addr(self) -> int:
        return self._trace[-1]

    def len(self) -> int:
        return len(self._trace)

    def add_address(self, addr: int):
        self._trace.append(addr)

    def add_use(
        self, addr_or_reg: Union[int, str], idx=None, label_override=None
    ):
        if idx is None:
            idx = self.current_idx
        self.uses[idx][addr_or_reg] = self.last_write.get(addr_or_reg, None)
        if label_override is not None:
            self.label_overrides[self.last_addr] = label_override

    def get_uses(self, idx: int) -> Dict[Union[int, str], int]:
        return self.uses[idx]

    def add_define(
        self,
        addr_or_reg: Union[int, str],
        value,
        idx=None,
        label_override=None,
    ):
        if idx is None:
            idx = self.current_idx
        if isinstance(value, int):
            value = hex(value)
        self.defines[idx][addr_or_reg] = value
        self.last_write[addr_or_reg] = idx
        if label_override is not None:
            self.label_overrides[self.last_addr] = label_override

    def get_defines(self, idx: int) -> Dict[Union[int, str], str]:
        return self.defines[idx]

    def _last_idx_of_address(self, address: int) -> int:
        # Find the last use of that address
        for idx in reversed(range(self.len())):
            if self._trace[idx] == address:
                return idx
        raise DataFlowException(f"Did not find target address {address:x}")


class DataFlow(IPlugin):
    """
    A collection of TargetInst. Dataflow techniques can be used on this
    collection to identify relationships between instructions

    TODO: Some instructions are conditional (movcond), meaning that even
    in this dynamic run, it may be unclear where each definition came
    from. We can deal with this multiple ways
      * Identify all possible sources it could have came from
      * Use the actual value that was given in order to give a guess on
        where the value came from.
    """

    def __init__(self, zelos: Zelos):
        super().__init__(zelos)
        self.dataflow_enabled = False
        if not zelos.config.taint and len(zelos.config.taint_when) == 0:
            return
        for zml_string in zelos.config.taint_when:
            zelos.internal_engine.zml_parser.trigger_on_zml(
                functools.partial(self.enable, zelos), zml_string,
            )
        if len(zelos.config.taint_when) == 0 and zelos.config.taint:
            self.enable(zelos)

    def enable(self, zelos: Zelos):
        """
        After calling this function, all dataflow in the target program
        will be tracked globally. The resulting flow is accessible
        through:
            - Dataflow.trace
            - Dataflow.ud_chain()
        """
        if self.dataflow_enabled:
            return
        self.dataflow_enabled = True
        self.trace = TraceInfo()
        self.define_use_map = {}
        self.reaching_defs: List[Dict[str, int]] = []

        def trace_inst(z, addr, size):

            self.trace.add_address(addr)
            # Sometimes the block hook doesn't work because the
            # definition of a block in tcg doesn't match up with the
            # size of the block. Need to look more into this.
            if addr not in self.define_use_map:
                self._update_tcg()
            # Delay adding register uses one address so that we can
            # get the value of the register after the instruction has
            # run.
            if self.trace.len() < 2:
                return
            last_addr = self.trace._trace[-2]
            (defs, _) = self.define_use_map[last_addr]
            idx = self.trace.len() - 2
            for register in defs:
                try:
                    reg_val = z.thread.get_reg(register)
                    self.trace.add_define(register, reg_val, idx=idx)
                except InvalidRegException:
                    # "uses" like "env" aren't registers, we may need
                    # To track them in the future though
                    pass

        def record_comments(z, addr, cmt):
            self.trace._addr_comment[addr] = cmt

        # This assumes memory hooks always run after instruction hooks.
        def trace_read(z, access, address, size, value):
            """ Add memory `use` to the trace """
            self.trace.add_use(address)

        def trace_write(z, access, address, size, value):
            """ Add memory `define` to the trace """
            self.trace.add_define(address, value)

        def trace_internal_read(z, access, address, size, value):
            """Add memory `use` to the trace originating from a zelos
            syscall emulation.
            """
            current_syscall = z.internal_engine.kernel._current_syscall
            if current_syscall is None:
                return
            for address in range(address, address + size):
                self.trace.add_use(address, label_override=current_syscall)

        def trace_internal_write(z, access, address, size, value):
            """Add memory `define` to the trace originating from a zelos
            syscall emulation.
            """
            current_syscall = z.internal_engine.kernel._current_syscall
            if current_syscall is None:
                return
            for i, address in enumerate(range(address, address + size)):
                self.trace.add_define(
                    address, value[i : i + 4], label_override=current_syscall
                )

        def trace_syscall(z, name, args, retval):
            """Add syscall arguments and return value uses and defines."""
            # FIXME: stack-based arguments will not be properly tracked
            #   here. For those, their addresses should be added. For
            #   example, syscalls with many arguments may put the
            #   overflow arguments on the stack. Uncommon.
            uses = set(z.internal_engine.kernel._REG_ARGS[: len(args._args)])
            defines = set([z.internal_engine.kernel._REG_RETURN])
            self.define_use_map[z.thread.getIP()] = (defines, uses)

        def trace_invalid_mem_access(z, access, address, size, value):
            """
            Handle invalid memory access violation by building a
            reverse taint graph from the crash site.
            """
            analyze_crash(self.zelos, self, self.trace.last_addr, address)
            return False

        zelos.plugins.trace.hook_comments(record_comments)
        zelos.hook_execution(HookType.EXEC.INST, trace_inst)
        zelos.hook_memory(HookType.MEMORY.READ, trace_read)
        zelos.hook_memory(HookType.MEMORY.WRITE, trace_write)
        zelos.hook_memory(HookType.MEMORY.INTERNAL_READ, trace_internal_read)
        zelos.hook_memory(HookType.MEMORY.INTERNAL_WRITE, trace_internal_write)
        zelos.hook_memory(HookType.MEMORY.INVALID, trace_invalid_mem_access)
        zelos.hook_syscalls(HookType.SYSCALL.AFTER, trace_syscall)

    def _update_tcg(self):
        """
        Attempts to get the tcg from the current address.
        """
        addr = self.zelos.thread.getIP()
        if addr in self.define_use_map:
            return
        insts = TCGParse().get_tcg(self.zelos)
        for i in insts:
            if self.state.arch == "x86":
                defines = self._adjust_x86_64_registers(i.defines())
                uses = self._adjust_x86_64_registers(i.uses())
            else:
                defines = i.defines()
                uses = i.uses()
            self.define_use_map[i.address] = (defines, uses)

    def _adjust_x86_64_registers(self, registers):
        return {
            "e" + reg[1:] if reg.startswith("r") else reg for reg in registers
        }

    def reverse_taint(self, start_addr: int):
        """ For testing """

        tg = TaintGraph(self, start_addr)
        return tg

    def _get_ida_func_name(self, address: int) -> str:
        if not hasattr(self, "names"):
            self.names = {
                n: a for a, n in self.zelos.plugins.ida.utils.Names()
            }

        return self.zelos.plugins.ida.idc.get_func_name(address)

    def _compute_defs(self):
        previous_dict = {}
        reaching_defs = [0] * len(self.trace._trace)
        for idx, addr in enumerate(self.trace._trace):
            (defs, _) = self.define_use_map.get(addr, ([], []))

            previous_dict.update({d: idx for d in defs})

            reaching_defs[idx] = previous_dict
            previous_dict = previous_dict.copy()
        self.reaching_defs = reaching_defs

    def ud_chain(self, target_idx: int) -> Dict[str, List[int]]:
        """
        Identifies the definition that reaches the current use.

        Returns:
            Dict of uses to the address of a potential definition.
        """
        if len(self.reaching_defs) == 0:
            self._compute_defs()
        ud_chain = defaultdict(list)
        target_address = self.trace._trace[target_idx]

        reaching_defs = self.reaching_defs[target_idx]

        (_, uses) = self.define_use_map.get(target_address, ([], []))
        uses = set(uses)  # we want a copy
        for u in uses:
            if u in ["env"]:
                continue
            reaching_def_idx = reaching_defs.get(u, None)
            if reaching_def_idx == target_idx:
                reaching_defs = self.reaching_defs[target_idx - 1]
                reaching_def_idx = reaching_defs.get(u, None)

            ud_chain[str(u)].append(reaching_def_idx)
        return ud_chain


def analyze_crash(z, dataflow, inst_address, mem_address):
    """
    Build a reverse taint graph from the crash site.
    """

    logger = dataflow.logger
    trace = dataflow.trace
    logger.notice("Execution finished.")
    taint_path = TaintGraph(dataflow, inst_address, mem_address)
    zelos_module_base = z.internal_engine.memory.get_module_base(
        z.target_binary_path
    )
    logger.info("Parsing DWARF info")
    annotate_with_dwarf_data(z, z.target_binary_path, trace._trace, taint_path)
    taint_path._addr2func = get_function_info(
        z.target_binary_path, taint_path, zelos_module_base
    )
    try:
        logger.info("Creating source taint graph")
        show_tainted_source(z, z.target_binary_path, trace._trace, taint_path)
        zcovPath = os.path.abspath(
            os.path.join(z.config.source_code_path, "crashd.zcov")
        )
        logger.notice(f"Wrote file: {zcovPath}")
    except Exception:
        logger.exception("Unable to show source code")
    if True:
        # This is all png graph generation
        from .render.graphviz import (
            render_reduced_path_taint_graph,
            render_path_taint_graph,
        )

        render_reduced_path_taint_graph(logger, taint_path)
        render_path_taint_graph(logger, taint_path, trace)

        # self.get_ida_taint_overlay(
        #     z.internal_engine.main_module.EntryPoint,
        #     trace,
        #     taint_path,
        #     open(crash_trace_file_name, "w"),
        # )
    return False
