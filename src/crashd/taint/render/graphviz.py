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
import html


def render_path_taint_graph(logger, taint_graph, trace, max_nodes=50):
    try:
        from graphviz import Digraph
    except Exception as e:
        return

    logger.info("Creating full taint graphviz")

    graph = Digraph(filename="cfg", format="png")

    included_keys = set()
    to_process = [trace._last_idx_of_address(taint_graph._start_addr)]
    while len(included_keys) < max_nodes and len(to_process) > 0:
        idx = to_process.pop(0)
        if idx in included_keys:
            continue
        graph.node(
            f"{idx:x}",
            taint_graph._addr_label(trace._trace[idx]),
            style="filled",
        )
        parents = taint_graph._path_parents.get(idx, [])
        to_process.extend(parents)
        included_keys.add(idx)

    for key, srcs in taint_graph._path.items():
        for src_key, src in srcs.items():
            if key not in included_keys or src_key not in included_keys:
                continue
            graph.edge(f"{key:x}", f"{src_key:x}", label=src.use_string())

    graph.render()


def render_reduced_path_taint_graph(logger, taint_graph, max_nodes=50):
    try:
        from graphviz import Digraph
    except Exception as e:
        return

    logger.info("Creating reduced taint graphviz")

    graph = Digraph(filename="reduced_cfg", format="png")

    included_keys = set()
    to_process = [taint_graph._start_addr]
    while len(included_keys) < max_nodes and len(to_process) > 0:
        addr = to_process.pop(0)
        if addr in included_keys:
            continue
        graph.node(
            f"{addr:x}", taint_graph._addr_label(addr), style="filled",
        )
        parents = taint_graph._reduced_path_parents.get(addr, [])
        to_process.extend(parents)
        included_keys.add(addr)

    for key, srcs in taint_graph._reduced_path.items():
        for src_key, src in srcs.items():
            if key not in included_keys or src_key not in included_keys:
                continue
            graph.edge(f"{key:x}", f"{src_key:x}", label=src.use_string())

    graph.render()


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


def render_source_graph(taint_graph, address_map, files):
    try:
        from graphviz import Digraph
    except Exception as e:
        return

    (nodes, edges) = get_nodes_and_edges(taint_graph, address_map)
    graph = Digraph(filename="source_cfg", format="png")
    graph.node_attr["shape"] = "box"
    node_ids = set()
    for n in nodes:
        file, line_num = address_map.get(n, (None, None))
        node_id = f"{file}{line_num}"
        if node_id in node_ids:
            continue
        node_ids.add(node_id)
        # Make the taint graph structure have source information
        values = list(taint_graph._reduced_path[n].values())
        if file not in files:
            src_line = f"0x{n:x}"
        else:
            context = 3
            src_lines = []
            for i in range(line_num - context, line_num + context + 1):
                if i < 0 or i >= len(files[file]):
                    continue
                line = html.escape(files[file][i].strip())
                if i == line_num and len(values) > 0:
                    line = (
                        f"<u>{line} /*val ="
                        f" {html.escape(str(values[0].val))}*/</u>"
                    )
                line += f'<br align="left"/>'
                src_lines.append(line)
            text = "".join(src_lines)
            src_line = f"<{text}>"
        node_id = f"{file}{line_num}"
        if node_id in node_ids:
            continue
        node_ids.add(node_id)
        # Make the taint graph structure have source information
        values = list(taint_graph._reduced_path[n].values())
        if file not in files:
            src_line = f"0x{n:x}"
        else:
            context = 3
            src_lines = []
            for i in range(line_num - context, line_num + context + 1):
                if i < 0 or i >= len(files[file]):
                    continue
                line = html.escape(files[file][i].strip())
                if i == line_num:
                    line = (
                        f"<u>{line} /*val = {html.escape(values[0].val)}*/</u>"
                    )
                line += f'<br align="left"/>'
                src_lines.append(line)
            text = "".join(src_lines)
            src_line = f"<{text}>"
        graph.node(node_id, label=src_line, style="filled")
    for src, dests in edges.items():
        srcfile, srcline_num = address_map.get(src, (None, None))
        for dest in dests:
            destfile, destline_num = address_map.get(dest, (None, None))
            graph.edge(
                f"{destfile}{destline_num}",
                f"{srcfile}{srcline_num}",
                label="",
            )
    graph.render()
