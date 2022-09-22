import inspect
from cryptography import x509
import typing
from typing import Callable, Type, TypeVar

T = TypeVar("T", bound=Type)


def inherit_default(func: Callable, param: str, cast: Type[T]) -> T:
    if (
        default := inspect.signature(func).parameters[param].default
    ) is inspect.Parameter.empty:
        raise ValueError(f"parameter {param} did not have a default")
    else:
        return typing.cast(cast, default)


def ext_type_to_ext(ext: x509.ExtensionType, critical: bool) -> x509.Extension:
    return x509.Extension(ext.oid, critical, ext)


def ext_to_ext_type(ext: x509.Extension) -> tuple[x509.ExtensionType, bool]:
    return ext.value, ext.critical
