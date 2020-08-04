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

import subprocess
import pickle
import base64
import os
import os.path as path
import tempfile

from zelos import IPlugin, CommandLineOption

CommandLineOption(
    "link_ida",
    type=str,
    default=None,
    help="Absolute path to an instance of IDA Pro",
)


class Ida(IPlugin):
    def __init__(self, zelos):
        super().__init__(zelos)
        self.initialized = False
        if zelos.config.link_ida is None:
            return

        ida_path = zelos.config.link_ida
        if not os.path.exists(ida_path):
            self.logger.error(f"Cannot resolve path to IDA executable.")
            return

        server_path = path.join(
            path.dirname(path.abspath(__file__)), "ida_server.py"
        )
        self.temp_dir = tempfile.TemporaryDirectory()

        ida_input_path = path.join(self.temp_dir.name, "ida_input")
        os.mkfifo(ida_input_path)

        ida_output_path = path.join(self.temp_dir.name, "ida_output")
        os.mkfifo(ida_output_path)

        p = subprocess.Popen(
            [
                ida_path,
                "-c",
                "-A",
                f'-S""{server_path} {ida_input_path} {ida_output_path}"" ',
                zelos.target_binary_path,
            ]
        )
        self.ida_input = open(ida_input_path, "w")
        self.ida_output = open(ida_output_path, "rb")

        def cleanup_proc():
            p.terminate()
            p.wait()
            self.temp_dir.cleanup()

        zelos.hook_close(cleanup_proc)

        self.initialized = True
        self.rebased = False

    def _auto_rebase(self):
        if self.rebased:
            return
        zelos = self.zelos
        zelos_base = zelos.internal_engine.files.get_module_base_by_name(
            zelos.target_binary_path
        )
        ida_base = self._raw_exec("idaapi.get_imagebase()")
        print(f"Adjusting imagebase from: {ida_base:x} to {zelos_base}")
        delta = zelos_base - ida_base

        # 8 == ida_segment.MSF_FIXONCE
        self._raw_exec(f"ida_segment.rebase_program({delta}, 8)")
        self.rebased = True

    def __getattr__(self, module_name):
        if self.initialized:
            return FauxModule(self, f"{module_name}")
        return super().__getattr__(self, module_name)

    @property
    def api(self):
        return FauxModule(self, f"idaapi")

    @property
    def utils(self):
        return FauxModule(self, f"idautils")

    @property
    def idc(self):
        return FauxModule(self, f"idc")

    def _exec(self, cmd: str) -> str:
        if not self.rebased:
            self._auto_rebase()
        return self._raw_exec(cmd)


    def _raw_exec(self, cmd: str) -> str:
        """
        Sends a command to IDA for execution
        """
        self.ida_input.write(f"{cmd}\n")
        self.ida_input.flush()
        data = self.ida_output.readline()
        data = base64.b64decode(data.strip())
        return pickle.loads(data, encoding="latin1")


class FauxModule:
    """
    This is a class used to identify what methods are being called on
    ida so that they can be passed as a string to the IdaServer
    """

    def __init__(self, ida_server_plugin, field_name):
        self._ida_server_plugin = ida_server_plugin
        self.name = field_name

    def __getattr__(self, field_name):
        return FauxModule(
            self._ida_server_plugin, self.name + "." + field_name
        )

    def _stringify(self, val):
        if type(val) == str:
            return '"' + val + '"'
        return str(val)

    def __call__(self, *args, **kwargs):
        arguments = [self._stringify(x) for x in args] + [
            f"{k}={self._stringify(v)}" for k, v in kwargs
        ]
        return self._ida_server_plugin._exec(
            self.name + "(" + ",".join(arguments) + ")"
        )
