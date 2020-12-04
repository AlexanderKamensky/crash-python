# -*- coding: utf-8 -*-
# vim:set shiftwidth=4 softtabstop=4 expandtab textwidth=79:

from crash.arch import CrashArchitecture, KernelFrameFilter, register_arch
from crash.arch import FetchRegistersCallback

import gdb

class _FRC_inactive_task_frame(FetchRegistersCallback): # pylint: disable=abstract-method
    def fetch_active(self, thread: gdb.InferiorThread, register: int) -> None:
        task = thread.info
        for reg in task.regs:
            try:
                thread.registers[reg].value = task.regs[reg]
            except KeyError:
                pass

    def fetch_scheduled(self, thread: gdb.InferiorThread,
                        register: int) -> None:
        task = thread.info.task_struct


        thread.registers['x19'].value = task['thread']['cpu_context']['x19']
        thread.registers['x20'].value = task['thread']['cpu_context']['x20']
        thread.registers['x21'].value = task['thread']['cpu_context']['x21']
        thread.registers['x22'].value = task['thread']['cpu_context']['x22']
        thread.registers['x23'].value = task['thread']['cpu_context']['x23']
        thread.registers['x24'].value = task['thread']['cpu_context']['x24']
        thread.registers['x25'].value = task['thread']['cpu_context']['x25']
        thread.registers['x26'].value = task['thread']['cpu_context']['x26']
        thread.registers['x27'].value = task['thread']['cpu_context']['x27']
        thread.registers['x28'].value = task['thread']['cpu_context']['x28']
        thread.registers['x29'].value = task['thread']['cpu_context']['fp']

        thread.registers['sp'].value = task['thread']['cpu_context']['sp']
        thread.registers['pc'].value = task['thread']['cpu_context']['pc']

        thread.info.stack_pointer = task['thread']['cpu_context']['sp']
        thread.info.valid_stack = True

class Aarch64Architecture(CrashArchitecture):
    ident = "aarch64"
    aliases = ["elf64-aarch64"]

    _fetch_registers = _FRC_inactive_task_frame

    def __init__(self) -> None:
        super(Aarch64Architecture, self).__init__()

    def setup_thread_info(self, thread: gdb.InferiorThread) -> None:
        task = thread.info.task_struct
        thread.info.set_thread_info(task['thread_info'].address)

    @classmethod
    def get_stack_pointer(cls, thread_struct: gdb.Value) -> int:
        return int(thread_struct['cpu_context']['sp'])

register_arch(Aarch64Architecture)
