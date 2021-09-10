
import ctypes
import frida
import time
import struct
import sys

from abc import ABC

import pymem.ressources.structure

from exceptions import MissingKwargError
from pymem import Pymem
from pymem.exception import WinAPIError, ProcessNotFound
from ReadWriteMemory import ReadWriteMemory
from script_info import ScriptInfo
from typing import Union, Callable, SupportsInt


class HookInto(ScriptInfo, ABC):
    on_enter: Union[Callable, str, None]
    on_leave: Union[Callable, str, None]

    def __init__(self, address: Union[str, None] = None, on_enter: Union[Callable, str, None] = None, on_leave: Union[Callable, str, None] = None, **kwargs):
        super().__init__(address=address, **kwargs)
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


class ValueReader(ScriptInfo, ABC):
    def __init__(self, address: Union[str, int, None] = None, **kwargs):
        super(ValueReader, self).__init__(**kwargs)
        self.address = address
        self.value = None
        self.btd6 = Pymem("BloonsTD6.exe")


class MoneyReader(ValueReader, ABC):
    def __init__(self, address: Union[str, int, None] = None, **kwargs):
        super(MoneyReader, self).__init__(address, **kwargs)

    def on_message(self, message, data):
        context = message.get('payload')
        if context:
            if context.get('r12') == '0x0':
                return
            print(message)
            self.address = int(context.get('rbx'), 0) + 0x28
            try:
                value = self.btd6.read_double(self.address)
                self.value = value if value > 1 else self.value
            except WinAPIError:
                pass

            print(f'address - {hex(self.address)}')
            print(f'money - {self.value}')


class CanPlaceReader(ValueReader, ABC):
    def __init__(self, address: Union[str, int, None] = None, **kwargs):
        super(CanPlaceReader, self).__init__(address, **kwargs)

    def on_message(self, message, data):
        print('=========')
        print(data)
        print(message)
        print('=========')


money_offset = 0x368380
placement_zone_offset = 0x529760
create_tower_offset = 0x9907a0  # Assets.Scripts.Simulation.Towers.TowerManager.CreateTower
is_eq_after_ref_check_offset = 0x6DE110  # Assets.Scripts.Models.SimulationBehaviors.CreateTowerActionSimBehaviorModel.IsEqualAfterReferenceCheck
area_place_holder_tower_offset = 0x9905A0  # Assets.Scripts.Simulation.Towers.TowerManager.CreateAreaPlaceholderTower
update_display_position_offset = 0x98EF70  # Assets.Scripts.Simulation.Towers.Props.Prop.UpdateDisplayPosition
can_place_offset = 0x634FA0


def main():
    game_assembly = None
    btd6 = None
    while not isinstance(btd6, Pymem):
        print('searching for btd6')
        try:
            btd6 = Pymem("BloonsTD6.exe")
        except ProcessNotFound:
            pass
    else:
        print('btd6 found')

    session = frida.attach('BloonsTD6.exe')

    while not isinstance(game_assembly, pymem.ressources.structure.MODULEINFO):
        print('searching for GameAssembly.dll')
        for module in btd6.list_modules():
            if module.name == 'GameAssembly.dll':
                game_assembly = module
                break

    print(hex(game_assembly.lpBaseOfDll))
    #load_money(session, game_assembly)
    load_can_place(session, game_assembly)
    sys.stdin.read()


def load_money(session, game_assembly):
    money_hook = session.create_script(str(HookInto(
        address=str(int(game_assembly.lpBaseOfDll + money_offset)),
        # on_enter='send(this.context);',
        on_leave='send(this.context);',
    )))
    money_reader = MoneyReader()
    money_hook.on('message', money_reader.on_message)
    money_hook.load()


def load_can_place(session, game_assembly):
    placement_hook = session.create_script(str(HookInto(
        address=str(int(game_assembly.lpBaseOfDll + can_place_offset)),
        on_leave='send(args);',
    )))
    placement_reader = CanPlaceReader()
    placement_hook.on('message', placement_reader.on_message)
    placement_hook.load()

# 0x368380
# 0x21090E8


if __name__ == '__main__':
    main()
