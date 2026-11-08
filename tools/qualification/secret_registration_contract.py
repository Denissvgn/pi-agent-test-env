"""Maintainer import path for the installed SDK registration contract module.

The maintained implementation is skill/scripts/operation_sdk/secret_registration_contract.py.
Importing this module returns that installed module object, so maintainer tests and
patches exercise the shipped bytes instead of a separately drifting copy.
"""
import sys
from pathlib import Path

_SCRIPTS = str(Path(__file__).resolve().parents[2] / 'skill/scripts')
if _SCRIPTS not in sys.path: sys.path.insert(0, _SCRIPTS)
from operation_sdk import secret_registration_contract as _installed  # noqa: E402

sys.modules[__name__] = _installed
