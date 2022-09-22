import inspect
from cryptography import x509
from typing import Any, Callable, ParamSpec, Type, TypeVar, Union, overload, cast

T = TypeVar("T")
U = TypeVar("U")
V = TypeVar("V")


def inherit_default(func: Callable, param: str, type_: Type[T]) -> T:
    if (
        default := inspect.signature(func).parameters[param].default
    ) is inspect.Parameter.empty:
        raise ValueError(f"parameter {param} did not have a default")
    elif not isinstance(default, type_):
        raise TypeError(f"parameter {param} did not have the right type")
    else:
        return default


def ext_type_to_ext(ext: x509.ExtensionType, critical: bool) -> x509.Extension:
    return x509.Extension(ext.oid, critical, ext)


def ext_to_ext_type(ext: x509.Extension) -> tuple[x509.ExtensionType, bool]:
    return ext.value, ext.critical


def attrs_type_passthrough(
    type_: Type[T], converter: Callable[[U], V]
) -> Callable[[T | U], T | V]:
    def _bingus(arg: T | U):
        if isinstance(arg, type_):
            return arg
        else:
            return converter(cast(U, arg))

    return _bingus
