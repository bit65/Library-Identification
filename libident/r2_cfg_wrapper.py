# Copyright (C) 2017 Thomas Rinsma / Riscure
# 
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
# 
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

# System imports
import os
import fcntl
from binascii import crc32
from subprocess import Popen, PIPE

# Packages
import r2pipe

class R2CFGWrapper:
    """
    Grab CFG and other data from r2.
    """

    def __init__(self, filename):
        flags = ["-e io.cache=true"]

        # Load the binary
        self.r2 = r2pipe.open(filename, flags)

        # Fix stderr issue with r2pipe
        if getattr(self.r2, "process") is not None:
            # self.r2.process.close()

            cmd = ["radare2", "-q0", filename]
            cmd = cmd[:1] + flags + cmd[1:]

            try:
                self.r2.process = Popen(cmd, shell=False, stdin=PIPE, stdout=PIPE, stderr=PIPE)
            except:
                raise Exception("ERROR: Cannot find radare2 in PATH")

            self.r2.process.stderr.close()
            self.r2.process.stdout.read(1)  # Reads initial \x00

            if self.r2.nonblocking:
                fd = self.r2.process.stdout.fileno()
                fl = fcntl.fcntl(fd, fcntl.F_GETFL)
                fcntl.fcntl(fd, fcntl.F_SETFL, fl | os.O_NONBLOCK)

        # Perform analysis
        # TODO: What types of analysis?
        self.r2.cmd("aaa")

        # Grab the function list
        self.functions = self.r2.cmdj("aflj")

    def get_cyclomatic_complexity_list(self):
        return [f['cc'] for f in self.functions]

    def get_cfg(self):
        return [self.r2.cmdj("agj @0x%x" % f['offset']) for f in self.functions]

    def get_bb_hashes(self):
        # CRC32 of the concatenation of all instruction types for every function
        for f in self.functions:
            fbb = self.r2.cmdj("agj @0x%x" % f['offset'])
            fops = []
            if len(fbb) < 1:
                continue
            for b in fbb[0]['blocks']:
                for i in b['ops']:
                    if 'type' in i:
                        fops.append(i['type'])
            yield crc32(''.join(fops))


    def read_function(self, function):
        return self.r2.cmdj("afij @0x%x" % function['offset'])
