"""The worker bootstrap reads its control frame from any inherited descriptor number."""
import errno
import json
import os
from pathlib import Path
import resource
import sys
from unittest import TestCase

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'skill/scripts'))
from operation_sdk import worker


class WorkerBootstrapDescriptorTests(TestCase):
    def free_descriptor_above_fd_setsize(self):
        soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
        if soft < 2048:
            wanted = 2048 if hard == resource.RLIM_INFINITY else min(hard, 2048)
            if wanted <= 1025: self.skipTest('descriptor limit does not reach above FD_SETSIZE')
            resource.setrlimit(resource.RLIMIT_NOFILE, (wanted, hard))
            self.addCleanup(resource.setrlimit, resource.RLIMIT_NOFILE, (soft, hard))
        limit = resource.getrlimit(resource.RLIMIT_NOFILE)[0]
        for number in range(1100, min(limit, 2048)):
            try: os.fstat(number)
            except OSError as error:
                if error.errno == errno.EBADF: return number
        self.skipTest('no free descriptor number above FD_SETSIZE')

    def test_control_frame_is_read_from_a_descriptor_above_fd_setsize(self):
        target = self.free_descriptor_above_fd_setsize()
        read, write = os.pipe()
        try:
            high = os.dup2(read, target)
            os.close(read); read = None
            body = json.dumps({'policy': {'fixture': True}}).encode()
            os.write(write, len(body).to_bytes(4, 'big') + body); os.close(write); write = None
            self.assertEqual(worker._initial(high), {'policy': {'fixture': True}})
        finally:
            for fd in (read, write, target):
                if fd is None: continue
                try: os.close(fd)
                except OSError: pass

    def test_closed_writer_without_a_complete_frame_still_fails_closed(self):
        read, write = os.pipe()
        try:
            os.write(write, b'\x00\x00'); os.close(write); write = None
            with self.assertRaises(ValueError): worker._initial(read)
        finally:
            for fd in (read, write):
                if fd is not None: os.close(fd)
