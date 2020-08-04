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

from typing import List, Set, Optional

import ctypes

ARITHMETIC_TCG_INSTS = [
    "add",
    "sub",
    "shr",
    "shl",
    "sar",
    "rotl",
    "rotr",
    "and",
    "nand",
    "xor",
    "or",
    "rem",
    "div",
    "mul",
]
IGNORED_TCG_INSTS = [
    "goto_tb",
    "exit_tb",
    "set_label",
    "end",
    "nop",
    "deposit",  # Not sure what this one does
    "discard",
]


def _decode_env_registers(offset):
    """
    Converts registers that are of the form env_$
    """
    reg = {
        "$0x328": "xmm1",
        "$0x330": "xmm1",
        "$0x338": "xmm2",
        "$0x340": "xmm2",
        "$0x348": "xmm3",
        "$0x350": "xmm3",
        "$0x358": "xmm4",
        "$0x360": "xmm4",
        "$0x368": "xmm5",
        "$0x370": "xmm5",
    }.get(offset, None)
    if reg is None:
        return set()
    return set([reg])


class TCGInst:
    """
    Represents Qemu TCG instruction-level uses and defines.
    """

    def __init__(self, inst_str: str):
        """
        Example `inst_str`s:
            1) "movi_i64 tmp3,$0x18f8d"
            2) "st_i64 tmp3,env,$0x80"
        """
        args = ""
        if " " in inst_str:
            self.name, args = inst_str.split(" ", 1)
        else:
            self.name = inst_str
        self.args = args.split(",")

    def __str__(self):
        return (
            f"({self.name}, {self.args}, def:{self.defines()},"
            f" use:{self.uses()})"
        )

    def __repr__(self):
        return self.__str__()

    def defines(self) -> Set[str]:
        """
        Returns the name of registers/temporaries that are defined
        by this instruction.
        """
        if self.is_type(["movcond_"]):
            return set([self.args[1]])
        if self.is_type(["st_i64"]):
            if self.args[1] == "env":
                return _decode_env_registers(self.args[2])
        if self.is_type(
            ARITHMETIC_TCG_INSTS
            + ["mov", "qemu_ld_", "ld", "ext", "neg", "not"]
        ):
            return set([self.args[0]])
        if self.is_type(
            IGNORED_TCG_INSTS + ["call", "br", "brcond", "setcond"]
        ):
            return set()
        if self.is_type(["qemu_st_", "st32_i64"]):
            # Do something with these?
            return set()
        print(
            "[TCGInst] `defines` not parsed:", self.name, ",".join(self.args)
        )
        return set()

    def uses(self) -> Set[str]:
        """
        Returns that name of registers/temporaries that are used
        by this instruction
        """
        if self.is_type(["ld_i64"]):
            if self.args[1] == "env":
                return _decode_env_registers(self.args[2])
        if self.is_type(["movcond"]):
            return set(self.args[2:])
        if self.is_type(["neg", "not"]):
            return set([self.args[0]])
        if self.is_type(["qemu_st_", "st"]):
            return set(self.args[0:2])
        if self.is_type(["call"]):
            return set(self.args[3:])
        if self.is_type(["mov_", "qemu_ld_", "brcond_", "ld", "ext"]):
            return set([self.args[1]])
        if self.is_type(["setcond_"]):
            return set(self.args[0:3])
        if self.is_type(ARITHMETIC_TCG_INSTS):
            return set(self.args[1:3])
        if self.is_type(IGNORED_TCG_INSTS + ["movi_", "br"]):
            return set()
        print(f"[TCGInst] `uses` not parsed: {self.name}", ",".join(self.args))
        return set()

    def is_type(self, list_of_types: List[str]) -> bool:
        """
        This takes a list of prefixes, and ensures that this inst is
        one of them
        """
        return any([self.name.startswith(t) for t in list_of_types])


class TargetInst:
    """
    Represents a group of TCGinsts that were generated from a single
    target architecture instruction.
    """

    def __init__(self, address, header_insts, tcginst_list):
        self.address = address
        self.header_insts = header_insts
        self.tcg_insts = tcginst_list
        # self._validate_tmps()  # For debugging purposes

    def __str__(self):
        inst_string = "\n  ".join([str(i) for i in self.tcg_insts])
        return (
            f"(Address: 0x{self.address:x}"
            + "\n  "
            + inst_string
            + "\n"
            + f"Defs: {self.defines()} Uses: {self.uses()})"
            + "\n"
        )

    def __repr__(self):
        return self.__str__()

    def uses(self) -> Set[str]:
        """
        Iterates over all the TCGInst's representing this instruction
        and accumulates all their uses.
        """
        use_strings = set()
        for inst in self.tcg_insts:
            use_strings.update(
                [
                    u
                    for u in inst.uses()
                    if not (u.startswith("tmp") or u.startswith("loc"))
                ]
            )
        return use_strings

    def defines(self) -> Set[str]:
        """
        Iterates over all the TCGInst's representing this instruction
        and accumulates all their defines.
        """
        def_strings = set()
        for inst in self.tcg_insts:
            def_strings.update(
                [
                    d
                    for d in inst.defines()
                    if not (d.startswith("tmp") or d.startswith("loc"))
                ]
            )
        return def_strings

    def _validate_tmps(self):
        """
        Ensure that every tmp variable has
          * > 0 def and > 0 uses
          * the def happens before the uses
        """
        defined = set()
        used = set()
        for inst in self.tcg_insts:
            defs = [d for d in inst.defines() if d.startswith("tmp")]
            defined.update(defs)
            uses = [u for u in inst.uses() if u.startswith("tmp")]
            for u in uses:
                assert u in defined, (self, u)
                used.add(u)
        assert used == defined, (self, used, defined)


class TCGParse:
    def __init__(self):
        pass

    def get_tcg(self, zelos):
        uc = zelos.internal_engine.emu._uc
        # TODO: Need to get the number of bytes that were written to
        # the buffer so that we can ensure that we got the full tcg
        # string from unicorn. For now, we just pick a big number and
        # use that.
        size = 1000000
        buffer = ctypes.create_string_buffer(size)
        uc.get_tcg_x86_64(buffer, size)

        insts = buffer.value.decode().split("\n")
        tcg_insts = [TCGInst(i.strip()) for i in insts if i != ""]
        assert tcg_insts[-1].name == "end"
        target_insts = self._split_into_target_insts(tcg_insts)
        return target_insts

    def _split_into_target_insts(self, tcg_list):
        """"""
        target_insts = None
        target_inst_grouping = []
        for i in tcg_list:
            target_inst_grouping.append(i)
            if i.name == "call" and i.args[0] == "uc_tracecode":
                if target_insts is None:
                    target_insts = []
                    target_inst_grouping = target_inst_grouping[-5:]
                else:
                    target_inst_grouping, new_inst_grouping = (
                        target_inst_grouping[:-5],
                        target_inst_grouping[-5:],
                    )
                    target_inst = self._make_target_inst(target_inst_grouping)
                    if target_inst is not None:
                        target_insts.append(target_inst)
                    target_inst_grouping = new_inst_grouping
        if len(target_inst_grouping) > 0:
            target_inst = self._make_target_inst(target_inst_grouping)
            if target_inst is not None:
                target_insts.append(target_inst)
        return target_insts

    def _make_target_inst(self, tcg_list) -> Optional[TargetInst]:
        """
        Cleanup tcg_list by removing some patterns that don't seem to
        contribute to the understanding of the original code
        """
        new_tcg_list = []
        i = 0
        while i < len(tcg_list):
            inst = tcg_list[i]
            if inst.name in ["nopn", "nop"]:
                i += 1
                continue
            new_tcg_list.append(inst)
            i += 1
        tcg_list = new_tcg_list

        addr = "????"
        call_inst = tcg_list[4]
        if call_inst.name == "call" and call_inst.args[0] == "uc_tracecode":
            # Unsure why this is, but in x86_64, I found that the first
            # instruction seems to be repeated, but with tmps instead of
            # the actual registers. It also seems like the second
            # argument to tracecode is 3 for the first call and 2 for
            # the others. I'll assume that 3's are always bad, and not
            # include those in the output
            if tcg_list[1].args[1] == "$0x3":
                return None

            addr_str = tcg_list[3].args[1]
            assert addr_str.startswith("$")
            addr = int(addr_str[1:], base=16)
            return TargetInst(addr, tcg_list[:5], tcg_list[5:])
        return TargetInst(addr, [], tcg_list)
