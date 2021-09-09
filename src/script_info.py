from functools import cached_property
from typing import Union, Optional, Callable


class ScriptInfo:
    code: Union[Callable, str]

    def __init__(self, **kwargs):
        self.kwargs = kwargs
        for k, v in self.kwargs.items():
            setattr(self, k, v)

    def __repr__(self) -> str:
        key_val_pairs = [f'{k} = {v}' for k, v in self.kwargs.items()]
        return f'{self.__class__.__name__}({", ".join(key_val_pairs)})'

    def on_message(self, message, data) -> None:
        """Holds callback for on_message"""
        raise NotImplementedError

    def on_authenticated(self, session_info) -> None:
        """Holds callback for on_authenticated"""
        raise NotImplementedError



