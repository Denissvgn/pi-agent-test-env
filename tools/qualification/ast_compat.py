"""Stable pinned AST rendering across supported maintainer Python versions.

The reviewed fingerprints use CPython's rendering that omits empty list fields.
Older interpreters include those fields. Only serialization of a detached copy
is normalized; executable nodes and nonempty/semantic fields remain unchanged.
"""
import ast
import copy


def pinned_dump(node):
    detached = copy.deepcopy(node)
    for child in ast.walk(detached):
        child._fields = tuple(name for name in child._fields
                              if not isinstance(getattr(child, name, None), list)
                              or getattr(child, name))
    return ast.dump(detached, include_attributes=False)
