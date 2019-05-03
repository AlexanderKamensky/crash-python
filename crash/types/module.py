# -*- coding: utf-8 -*-
# vim:set shiftwidth=4 softtabstop=4 expandtab textwidth=79:

from typing import Iterable, Tuple

import gdb
from crash.types.list import list_for_each_entry
from crash.util.symbols import Symvals, Types

symvals = Symvals([ 'modules' ])
types = Types([ 'struct module' ])

def for_each_module() -> Iterable[gdb.Value]:
    """
    Iterate over each module in the modules list

    Yields:
        gdb.Value(<struct module>): The next module on the list

    """
    for module in list_for_each_entry(symvals.modules, types.module_type,
                                      'list'):
        yield module

def for_each_module_section(module: gdb.Value) -> Iterable[Tuple[str, int]]:
    """
    Iterate over each ELF section in a loaded module

    This routine iterates over the 'sect_attrs' member of the 'struct module'
    already in memory.  For ELF sections from the module at rest, use
    pyelftools on the module file.

    Args:
        module (gdb.Value): The struct module to iterate

    Yields:
        (str, int): A 2-tuple containing the name and address of the section
    """
    attrs = module['sect_attrs']

    for sec in range(0, attrs['nsections']):
        attr = attrs['attrs'][sec]
        name = attr['name'].string()
        if name == '.text':
            continue

        yield (name, int(attr['address']))
