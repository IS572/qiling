#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org)

import sys

sys.path.append("..")
from qiling import *

if __name__ == "__main__":
    ql = Qiling(["rootfs/mips32_deb6/bin/sh"], "rootfs/mips32_deb6", output="debug")
    # patch libc.fork() to bypass assertion
    ql.patch(0xba104, b'\x00\x00\x00\x00', b'libc.so.6')
    ql.multithread = True
    ql.run()
