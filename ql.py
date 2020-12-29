#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org) 


import argparse, os, string, sys, ast, unicorn
from binascii import unhexlify

from qiling import *
from qiling.const import QL_ARCH
from qiling.__version__ import __version__ as ql_version
from qiling.extensions.coverage import utils as cov_utils
from qiling.extensions.report import generate_report

def parse_args(parser, commands):
    # Divide argv by commands
    split_argv = [[]]
    for c in sys.argv[1:]:
        if c in commands.choices:
            split_argv.append([c])
        else:
            split_argv[-1].append(c)
    
    # Initialize namespace
    args = argparse.Namespace()
    for c in commands.choices:
        setattr(args, c, None)

    # Parse each command
    parser.parse_args(split_argv[0], namespace=args)  # Without command
    for argv in split_argv[1:]:  # Commands
        n = argparse.Namespace()
        setattr(args, argv[0], n)
        parser.parse_args(argv, namespace=n)
    return args

def version():
    print("qltool for Qiling %s, using Unicorn %s" %(ql_version, unicorn.__version__))

def usage():
    version()
    print("\nUsage: ./qltool OPTIONS")

    print("\n\nWith binary file:")
    print("\t ./ql.py -f examples/rootfs/x8664_linux/bin/x8664_hello --rootfs  examples/rootfs/x8664_linux/")
    print("\t ./ql.py -f examples/rootfs/mips32el_linux/bin/mips32el_hello --rootfs examples/rootfs/mips32el_linux")

    print("\n\nWith binary file and Qdb:")
    print("\t ./ql.py -f examples/rootfs/mips32el_linux/bin/mips32el_hello --rootfs examples/rootfs/mips32el_linux --qdb")
    print("\t ./ql.py -f examples/rootfs/mips32el_linux/bin/mips32el_hello --rootfs examples/rootfs/mips32el_linux --qdb --rr")

    print("\n\nWith binary file and gdbserver:")
    print("\t ./ql.py -f examples/rootfs/x8664_linux/bin/x8664_hello --gdb 127.0.0.1:9999 --rootfs examples/rootfs/x8664_linux")

    print("\n\nWith binary file and additional argv:")
    print("\t ./ql.py -f examples/rootfs/x8664_linux/bin/x8664_args --rootfs examples/rootfs/x8664_linux --args test1 test2 test3")

    print("\n\nwith binary file and various output format:")
    print("\t ./ql.py -f examples/rootfs/mips32el_linux/bin/mips32el_hello --rootfs examples/rootfs/mips32el_linux --output=disasm")
    print("\t ./ql.py -f examples/rootfs/mips32el_linux/bin/mips32el_hello --rootfs examples/rootfs/mips32el_linux --strace -e open")
    print("\t ./ql.py -f examples/rootfs/mips32el_linux/bin/mips32el_hello --rootfs examples/rootfs/mips32el_linux --strace -e open --log-dir=qlog")
    
if __name__ == '__main__':

    # argparse setup
    parser = argparse.ArgumentParser()
    parser.add_argument('-f', '--filename', required=False, default=None, metavar="FILE", dest="filename", help="filename")
    parser.add_argument('--rootfs', required=False, default="/home/user/apps/qiling/examples/rootfs/mips32_deb6", help='emulated rootfs')
    parser.add_argument('--args', required=False, default=[], nargs=argparse.REMAINDER, dest="args", help="args")
    parser.add_argument('run_args', default=[], nargs=argparse.REMAINDER)

    parser.add_argument('-o', '--output', required=False, default='default',
                            help='output mode, options are off, debug , disasm, dump')
    parser.add_argument('-v', '--verbose', required=False, default=1, dest='verbose',
                            help='verbose mode, must be int and use with --debug or --dump')
    parser.add_argument('--env', required=False, default='', metavar="FILE", dest="env", help="Pickle file containing an environment dictionary")                            
    parser.add_argument('-g', '--gdb', required=False, help='enable gdb server')
    parser.add_argument('--qdb', action='store_true', required=False, help='attach Qdb at entry point, it\'s MIPS, ARM(THUMB) supported only for now')
    parser.add_argument('--follow_execve', action='store_true', required=False, help='follow execve system call to debug new process')
    parser.add_argument('--rr', action='store_true', required=False, help='switch on record and replay feature in qdb, only works with --qdb')
    parser.add_argument('--profile', required=False, dest='profile', help="Define customized profile")
    parser.add_argument('--strace', action='store_true', default=False, dest='strace', help='Run in strace mode')
    parser.add_argument('--dump', action='store_true', default=False, dest='dump', help='Enable Debug + Diassembler mode')
    parser.add_argument('--debug', action='store_true', default=False, dest='debug', help='Enable Debug mode')
    parser.add_argument('--disasm', action='store_true', default=False, dest='disasm', help='Run in disassemble mode')
    parser.add_argument('--console', required=False, default=True, dest='console', help='display in console')
    parser.add_argument('-e', '--filter', metavar="FUNCTION NAME", required=False, dest="filter", default=None, 
                            help="Only work with strace mode, you can choose what to be printout, for multiple function calls should be separated by comma")
    parser.add_argument('--log-dir', required=False, metavar="DIRECTORY NAME", dest='log_dir', default=None, help='the destinartion you want to store you log')
    parser.add_argument('--trace', action='store_true', default=False, dest='trace', help='Run in strace mode')
    parser.add_argument('--root', action='store_true', default=False, dest='root', help='Enable sudo required mode')
    parser.add_argument('--debug_stop', action='store_true', default=False, dest='debug_stop', 
                            help='Stop running while encounter any error (only use it with debug mode)')
    parser.add_argument('-m','--multithread', action='store_true', default=True, dest='multithread', help='Run in multithread mode')
    parser.add_argument('--timeout', required=False, help='Emulation timeout')
    parser.add_argument('-c', '--coverage-file', required=False, default=None, dest='coverage_file', help='Code coverage file name')
    parser.add_argument('--coverage-format', required=False, default='drcov', dest='coverage_format',
                             choices=cov_utils.factory.formats, help='Code coverage file format')
    parser.add_argument('--json', action='store_true', default=False, dest='json', help='Print a json report of the emulation')
    options = parser.parse_args()

    # var check
    if options.strace:
        options.output = "default"
    elif options.trace:
        options.output = "disasm"
    elif options.dump:
        options.output = "dump"
    elif options.debug:
        options.output = "debug"
    elif options.disasm:
        options.output = "disasm"
    else:
        options.output = "default"              

    if options.profile:
        options.profile = str(options.profile)

    if options.console == 'False':
        options.console = False
    else:
        options.console = True

    if options.env != '':
        if os.path.exists(options.env):
            import pickle
            with open(options.env, 'rb') as f:
                env = pickle.load(f)
        else:
            env = ast.literal_eval(options.env)
    else:
        env = {}
    
    if type(options.verbose) != int and options.output not in ("debug", "dump"):
        print("ERROR: verbose mode, must be int and use with --debug or --dump")
        usage()

    if options.debug_stop and not (options.dump or options.debug):
        print("ERROR: debug_stop must use with either dump or debug mode")
        usage()
    
    # with argv
    if options.filename is not None and options.run_args == []:
        ql = Qiling(filename=[options.filename] + options.args, rootfs=options.rootfs, profile=options.profile, output=options.output, console=options.console, log_dir=options.log_dir, env=env)

    # Without argv
    elif options.filename is None and options.args == [] and options.run_args != []:
        ql = Qiling(filename=options.run_args, rootfs=options.rootfs, profile=options.profile, output=options.output, console=options.console, log_dir=options.log_dir, env=env)
    
    else:
        print("ERROR: Command error!")
        usage()

    # attach Qdb at entry point
    if options.qdb == True:
        from qiling.debugger.qdb import QlQdb as Qdb

        Qdb(ql, rr=options.rr)

    # ql execute additional options
    if options.gdb:
        ql.debugger = options.gdb
        ql.follow_execve = options.follow_execve

    if options.debug_stop and (options.dump or options.debug):
        ql.debug_stop = True
        
    if options.root:
        ql.root = True

    if options.multithread:
        ql.multithread = True
        # patch libc fork assertion to ignore `self->tid!=ppid`

    if options.verbose:
        ql.verbose = options.verbose
    else:
        ql.verbose = 1

    if options.filter:
        ql.filter = options.filter


    timeout = 0
    if options.timeout != None:
        timeout = int(options.timeout)
    
    # patch libc.fork() to bypass assertion
    ql.patch(0xba104, b'\x00\x00\x00\x00', b'libc.so.6')

    # ql run
    with cov_utils.collect_coverage(ql, options.coverage_format, options.coverage_file):
        ql.run(timeout=timeout)

    if options.json:
        print(generate_report(ql, pretty_print=True))

    exit(ql.os.exit_code)

