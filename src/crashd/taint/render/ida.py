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
def get_ida_taint_overlay(entrypoint, trace, taint_graph, file):
    import json

    # Find all addresses that are not sources of another address.
    # These should be highlighted as the beginning of the taint
    # Or end of reverse taint. However you want to look at it.
    addr_seen = {}
    for idx, sources in taint_graph._path.items():
        addr = trace._trace[idx]
        addr_seen[addr] = False
        for src in sources:
            addr_seen[src[0]] = True

    out_map = {
        "entrypoint": entrypoint,
        "comments": [],
    }
    for addr, src in path.items():
        comment = ", ".join([f"0x{x[0]:x}|{x[1]}" for x in src])
        comment_struct = {
            "address": addr,
            "thread_id": "main",
            "text": f" <- {comment}",
        }
        if src[0][1] == "user_taint":
            comment_struct["color"] = 0xE16563
        if not addr_seen[addr]:
            comment_struct["color"] = 0x81CD4E

        # green

        out_map["comments"].append(comment_struct)

    r = json.dumps(out_map)
    loaded_r = json.loads(r)
    file.write("DISAS\n" + json.dumps(loaded_r, indent=4, sort_keys=True))