from enum import Enum
from typing import Iterable


class Permission(str, Enum):
    pass


def permission_values(
    permissions: Iterable[Permission],
) -> frozenset[str]:
    """
    Convert Permission enums into normalized permission strings.
    """
    values: set[str] = set()

    for permission in permissions:
        if isinstance(permission, Permission):
            values.add(permission.value)
        else:
            raise TypeError(
                "Permissions must be Permission instances"
            )

    return frozenset(values)
        