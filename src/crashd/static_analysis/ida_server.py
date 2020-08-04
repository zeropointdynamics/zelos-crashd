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

# Python2 Script for Ida

from idautils import *
from idaapi import *
import idc
import pickle
import base64
import types


def write_data(out, data):
    data = base64.b64encode(pickle.dumps(data)) + "\n"
    out.write(data)
    out.flush()


in_path = idc.ARGV[1]
out_path = idc.ARGV[2]

p = open(in_path, "r")
out = open(out_path, "wb")

Wait()
ea = BeginEA()
result = None
while True:
    try:
        cmd = p.readline()
        exec_command = "global result; result = %s" % cmd
        try:
            exec_command = "global result; result = %s" % cmd
            exec(exec_command)
        except Exception as e:
            write_data(out, str(e) + " | exec_command : " + exec_command)
        else:
            if isinstance(result, types.GeneratorType):
                result = list(result)
            write_data(out, result)
    except Exception as e:
        write_data(out, "Error in plugin: " + str(e))

idc.Exit(0)
