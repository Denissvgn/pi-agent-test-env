"""Private framing is bounded, exact, deadline-aware and never logs its body."""
import json
import os
from pathlib import Path
import sys
import time
from unittest import TestCase

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'skill/scripts'))
from operation_sdk import wire


class SDKWireTests(TestCase):
    def reject(self, callback):
        with self.assertRaises(wire.SDKError) as caught: callback()
        self.assertEqual(str(caught.exception), '<sdk>')
        self.assertLessEqual(len(repr(caught.exception)), 8)

    def test_canonical_utf8_document_and_duplicate_nonfinite_surrogate_rejection(self):
        value = {'schema': 1, 'text': 'é'}
        self.assertEqual(wire.decode(wire.encode(value, 1024), 1024), value)
        for body in (b'{"x":1,"x":2}', b'{"x":NaN}', b'{"x":1e999}', b'{"x":"\\ud800"}', b'\xff'):
            self.reject(lambda: wire.decode(body, 1024))

    def test_nested_and_entry_bounds_are_checked_before_recursion_or_large_allocation(self):
        self.reject(lambda: wire.decode(b'[' * 100 + b'0' + b']' * 100, 1024))
        self.reject(lambda: wire.encode({'text': 'x' * 4096}, 128))
        self.reject(lambda: wire.decode(b'{}', True))
        self.reject(lambda: wire.encode({'x': object()}, 1024))

    def test_decoder_accepts_fragmented_exact_frame_and_requires_complete_eof(self):
        body = wire.encode({'schema': 1}, 1024); decoder = wire.Frame(1024)
        frame = len(body).to_bytes(4, 'big') + body
        for byte in frame: decoder.feed(bytes([byte]))
        self.assertEqual(decoder.finish(), body)
        self.reject(lambda: decoder.feed(b'x'))
        missing = wire.Frame(1024); missing.feed(frame[:-1]); self.reject(missing.finish)

    def test_oversized_header_does_not_allocate_a_body(self):
        decoder = wire.Frame(16)
        self.reject(lambda: decoder.feed((17).to_bytes(4, 'big')))
        self.assertEqual(decoder.buffered_bytes, 0)

    def test_native_pipe_frame_and_eof_are_distinct_from_write_confirmation(self):
        read_fd, write_fd = os.pipe()
        try:
            body = wire.encode({'schema': 1, 'text': 'literal-fake'}, 1024)
            progress = wire.write_frame(write_fd, body, time.monotonic() + 1)
            self.assertEqual(progress, len(body) + 4)
            os.close(write_fd); write_fd = None
            self.assertEqual(wire.read_frame(read_fd, 1024, time.monotonic() + 1, eof=True), body)
        finally:
            os.close(read_fd)
            if write_fd is not None: os.close(write_fd)

    def test_absent_eof_times_out_even_with_a_complete_body(self):
        read_fd, write_fd = os.pipe()
        try:
            wire.write_frame(write_fd, b'{}', time.monotonic() + 1)
            self.reject(lambda: wire.read_frame(read_fd, 1024, time.monotonic() + 0.02, eof=True))
        finally: os.close(read_fd); os.close(write_fd)

    def test_fixed_public_status_is_smaller_than_any_application_credential(self):
        for accepted in (False, True):
            packet = wire.public_status(3, accepted)
            self.assertLess(len(packet), 16)
            self.assertEqual(wire.decode_status(packet), (3, accepted))
            self.assertTrue(all(byte < 32 for byte in packet))
        for code in range(256):
            packet = wire.public_status(code, False)
            self.assertTrue(all(byte < 32 for byte in packet))
            self.assertEqual(wire.decode_status(packet), (code, False))
        self.reject(lambda: wire.public_status(True, False))
        self.reject(lambda: wire.decode_status(b'fake-private-key-0123456789'))

    def test_private_value_wrapper_never_renders_value_or_mutable_original(self):
        value = {'text': 'fixture-private-value-0123456789'}
        private = wire.PrivateData(value)
        value['text'] = 'changed'
        self.assertNotIn('fixture', repr(private))
        self.assertNotIn('fixture', str(private))
        self.assertEqual(private.get()['text'], 'fixture-private-value-0123456789')
        private.get()['text'] = 'changed'
        self.assertEqual(private.get()['text'], 'fixture-private-value-0123456789')

    def test_encode_retains_the_original_size_refusal_code(self):
        with self.assertRaises(wire.SDKError) as caught: wire.encode({'body': 'x' * 100}, 1)
        self.assertEqual(caught.exception.code, 5)

    def test_rejected_frame_is_permanently_spent(self):
        decoder = wire.Frame(1)
        with self.assertRaises(wire.SDKError) as caught: decoder.feed((2).to_bytes(4, 'big'))
        self.assertEqual(caught.exception.code, 5)
        with self.assertRaises(wire.SDKError): decoder.feed(b'ab')
        with self.assertRaises(wire.SDKError): decoder.finish()
