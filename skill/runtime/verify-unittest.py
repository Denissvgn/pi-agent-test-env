#!/usr/bin/env python3
"""Independent unittest acceptance: zero discovered tests is a failure."""
import argparse
import unittest
import sys
from pathlib import Path

p = argparse.ArgumentParser()
p.add_argument('--start-dir', default='tests')
p.add_argument('--pattern', default='test*.py')
p.add_argument('--top-level-dir',help='Import root for a package test layout; defaults to the selected working directory')
a = p.parse_args()
top=Path(a.top_level_dir or Path.cwd()).resolve()
sys.path.insert(0,str(top))
suite = unittest.defaultTestLoader.discover(a.start_dir, pattern=a.pattern,top_level_dir=str(top) if a.top_level_dir else None)
if suite.countTestCases() == 0:
    raise SystemExit('FAIL: no acceptance tests discovered')
result = unittest.TextTestRunner(verbosity=2).run(suite)
print(f'INDEPENDENT_TESTS_RUN={result.testsRun}')
raise SystemExit(0 if result.wasSuccessful() else 1)
