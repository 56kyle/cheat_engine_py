
import ctypes
import frida
import sys

from abc import ABC
from exceptions import MissingKwargError
from pymem import Pymem
from script_info import ScriptInfo
from typing import Optional, Union, Callable


class HookInto(ScriptInfo, ABC):
    on_enter: Union[Callable, str, None]
    on_leave: Union[Callable, str, None]

    def __init__(self, address: Union[str, None] = None, on_enter: Union[Callable, str, None] = None, on_leave: Union[Callable, str, None] = None, **kwargs):
        super().__init__(**kwargs)
        self.on_enter = on_enter
        self.on_leave = on_leave

    def __str__(self):
        address = self.kwargs.get('address')
        if not address:
            raise MissingKwargError('Missing kwarg \'address\'')
        return self.code(address)

    def code(self, address) -> str:
        on_enter_text = self.on_enter_container()
        on_leave_text = self.on_leave_container()
        return f'''
        Interceptor.attach(ptr("{address}"), {{
            {on_enter_text}
            {on_leave_text}
        }});
        ''' if on_enter_text or on_leave_text else ''

    def on_enter_container(self) -> str:
        on_enter_content = self.on_enter_content()
        return f'''onEnter: function(args) {{
            {self.on_enter}
        }},
        ''' if on_enter_content else ''

    def on_enter_content(self) -> str:
        if callable(self.on_enter):
            return self.on_enter(**self.kwargs)
        return self.on_enter

    def on_leave_container(self) -> str:
        on_leave_content = self.on_leave_content()
        return f'''onLeave: function(args) {{
            {on_leave_content}
         }},
         ''' if on_leave_content else ''

    def on_leave_content(self) -> str:
        if callable(self.on_leave):
            return self.on_leave(**self.kwargs)
        return self.on_leave


def on_message(message, data):
    print(hex(message['payload']))
    print(message)
    print(data)


def main():
    game_assembly = None
    btd6 = Pymem("BloonsTD6.exe")
    for module in btd6.list_modules():
        if module.name == 'GameAssembly.dll':
            game_assembly = module
            break
    print(game_assembly)
    session = frida.attach("BloonsTD6.exe")
    hook = session.create_script(str(HookInto(
        address=str(int(game_assembly.lpBaseOfDll + 0x368380)),
        on_enter='send(args[0].toInt32(), this.context.rax);',
        on_leave='send(args[0].toInt32(), this.context.rax);',
    )))
    hook.on('message', on_message)
    hook.load()
    sys.stdin.read()


# 0x368380
# 0x21090E8

if __name__ == '__main__':
    main()
