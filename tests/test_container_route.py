# Specification for container_route.classify(url) and container_route.host_route(url)
#
# Both take a URL as a str.
#
# classify(url) returns one of the strings 'loopback', 'docker-host', 'other'.
#   The host is the host part of the URL: without any user information, without
#   the port and, for an IPv6 literal, without the square brackets. Host names
#   are compared without regard to letter case.
#   C1  'loopback': the hosts localhost, 0.0.0.0 and ::1, and every IPv4
#       address in 127.0.0.0/8 (127.0.0.0 to 127.255.255.255).
#   C2  'docker-host': the hosts host.docker.internal and
#       gateway.docker.internal.
#   C3  'other': every other host. This includes names that merely contain or
#       extend a special name (localhost.example.com, notlocalhost,
#       host.docker.internal.example.com), IPv4 addresses next to the loopback
#       range (126.255.255.255, 128.0.0.0), 0.0.0.1, and IPv6 literals other
#       than ::1. A special name that appears only in the user information, the
#       path or the query does not make the URL special.
#   C4  A port, a path, a query, user information and an IPv6 literal with a port
#       (http://[::1]:8080/) do not change the class: it is decided by the host
#       only.
#   C5  The scheme must be http or https (in any letter case). Any other scheme,
#       a missing scheme (including 'localhost:8080/x', '//localhost/' and a
#       plain path), an empty string, or a URL without a host (for example
#       'http://', 'http:///x', 'http://:8080/') raises ValueError.
#
# host_route(url) returns the URL as text with only the host replaced.
#   H1  When the class is 'docker-host' the host text is replaced by 127.0.0.1
#       and every other character of the URL is kept exactly: scheme, user
#       information, port, path, query and fragment. A URL with no path or no
#       port stays without one. The replacement is of the host only, so a
#       docker host name in the query or path is left as it is.
#   H2  For the classes 'loopback' and 'other' the URL is returned unchanged,
#       character for character.
#   H3  A URL that classify rejects raises ValueError.
#
# Boundaries covered below: the first and last address of 127.0.0.0/8 and the
# addresses just outside it, IPv6 literals with and without a port, host names
# in upper case, special names in the user information / path / query, URLs
# with no path, no port, a query without a path and a fragment, and the invalid
# URL forms of C5.
#
# The file runs in the repository and, unchanged, in a scratch project. It puts
# skill/scripts (when present) and the working directory on the import path and
# skipped as a whole, with the reason "module not present", while the module
# container_route does not exist. Once it exists, every case runs and an import
# error raised inside it is reported, not hidden.

import importlib
import sys
import unittest
from pathlib import Path

_HERE = Path(__file__).resolve().parent
for _base in (_HERE.parent, Path.cwd()):
    for _dir in (_base / "skill" / "scripts", _base):
        if _dir.is_dir() and str(_dir) not in sys.path:
            sys.path.append(str(_dir))


def _load():
    try:
        return importlib.import_module("container_route")
    except ModuleNotFoundError as exc:
        if exc.name == "container_route":
            return None
        raise


container_route = _load()
if container_route is None:
    if __name__ == "__main__":
        print("skipped: module not present")
        sys.exit(0)
    raise unittest.SkipTest("module not present")

LOOPBACK_URLS = (
    "http://localhost",
    "http://localhost/",
    "http://LOCALHOST:8080/x",
    "https://Localhost:443/a/b?c=d",
    "http://0.0.0.0/",
    "https://0.0.0.0:9/",
    "http://127.0.0.1",
    "http://127.0.0.1:1234/p?q=1",
    "http://127.0.0.0/",
    "http://127.255.255.255/",
    "http://127.1.2.3:80/",
    "http://[::1]",
    "http://[::1]/",
    "http://[::1]:8080/",
    "https://[::1]:443/a?b=c",
    "http://user@localhost/",
    "http://example.com@localhost/",
    "HTTP://localhost/",
)

DOCKER_HOST_URLS = (
    "http://host.docker.internal",
    "http://host.docker.internal/",
    "http://host.docker.internal:8080/",
    "https://gateway.docker.internal:443/x",
    "http://gateway.docker.internal",
    "http://Host.Docker.Internal/",
    "http://HOST.DOCKER.INTERNAL:80/p?q=1",
    "HTTPS://host.docker.internal/",
)

OTHER_URLS = (
    "http://example.com",
    "https://example.com:8443/path?x=1",
    "http://localhost.example.com/",
    "http://notlocalhost/",
    "http://localhost1/",
    "http://127.0.0.1.example.com/",
    "http://host.docker.internal.example.com/",
    "http://my.host.docker.internal/",
    "http://docker.internal/",
    "http://126.255.255.255/",
    "http://128.0.0.0/",
    "http://128.0.0.1:80/",
    "http://0.0.0.1/",
    "http://10.0.0.1:80/",
    "http://192.168.1.1/",
    "http://[::2]/",
    "http://[2001:db8::1]/",
    "http://[2001:db8::1]:8080/",
    "http://[::]/",
    "http://localhost@example.com/",
    "http://localhost:8080@example.com/",
    "http://example.com/localhost",
    "http://example.com?host=localhost",
    "http://example.com:80/host.docker.internal",
)

INVALID_URLS = (
    "",
    "localhost",
    "localhost:8080",
    "localhost:8080/path",
    "host.docker.internal",
    "//localhost/",
    "/relative/path",
    "ftp://localhost/",
    "file:///etc/hosts",
    "ws://localhost/",
    "mailto:user@example.com",
    "http:localhost",
    "http://",
    "https://",
    "http:///path",
    "http://:8080/",
    "http://user@/",
    "http://[::1",
)


class ClassifyTests(unittest.TestCase):
    def test_loopback_hosts(self):
        for url in LOOPBACK_URLS:
            with self.subTest(url=url):
                self.assertEqual(container_route.classify(url), "loopback")

    def test_docker_hosts(self):
        for url in DOCKER_HOST_URLS:
            with self.subTest(url=url):
                self.assertEqual(container_route.classify(url), "docker-host")

    def test_other_hosts(self):
        for url in OTHER_URLS:
            with self.subTest(url=url):
                self.assertEqual(container_route.classify(url), "other")

    def test_loopback_range_edges(self):
        classify = container_route.classify
        self.assertEqual(classify("http://127.0.0.0"), "loopback")
        self.assertEqual(classify("http://127.255.255.255"), "loopback")
        self.assertEqual(classify("http://126.255.255.255"), "other")
        self.assertEqual(classify("http://128.0.0.0"), "other")

    def test_ipv6_literal_with_and_without_port(self):
        classify = container_route.classify
        self.assertEqual(classify("http://[::1]"), "loopback")
        self.assertEqual(classify("http://[::1]:1"), "loopback")
        self.assertEqual(classify("http://[::1]:65535/"), "loopback")
        self.assertEqual(classify("http://[::2]:8080/"), "other")
        self.assertEqual(classify("http://[2001:db8::1]:8080/"), "other")

    def test_invalid_urls_raise_value_error(self):
        for url in INVALID_URLS:
            with self.subTest(url=url):
                with self.assertRaises(ValueError):
                    container_route.classify(url)

    def test_result_is_one_of_three_strings(self):
        urls = LOOPBACK_URLS + DOCKER_HOST_URLS + OTHER_URLS
        for url in urls:
            with self.subTest(url=url):
                self.assertIn(
                    container_route.classify(url),
                    ("loopback", "docker-host", "other"),
                )


class HostRouteTests(unittest.TestCase):
    def test_docker_host_is_replaced_by_loopback_address(self):
        cases = (
            ("http://host.docker.internal", "http://127.0.0.1"),
            ("http://host.docker.internal/", "http://127.0.0.1/"),
            ("http://gateway.docker.internal", "http://127.0.0.1"),
            ("http://host.docker.internal:8080/", "http://127.0.0.1:8080/"),
            (
                "http://host.docker.internal:8080/api/v1?x=1&y=2",
                "http://127.0.0.1:8080/api/v1?x=1&y=2",
            ),
            (
                "https://gateway.docker.internal:8443/a%20b?q=a+b",
                "https://127.0.0.1:8443/a%20b?q=a+b",
            ),
            ("https://host.docker.internal:443/", "https://127.0.0.1:443/"),
            ("http://HOST.Docker.INTERNAL:80/", "http://127.0.0.1:80/"),
            ("http://host.docker.internal?x=1", "http://127.0.0.1?x=1"),
            ("http://host.docker.internal/?x=1", "http://127.0.0.1/?x=1"),
            ("http://host.docker.internal:9000/p?q=1#frag", "http://127.0.0.1:9000/p?q=1#frag"),
            ("http://host.docker.internal/#top", "http://127.0.0.1/#top"),
            ("http://user@host.docker.internal:1/", "http://user@127.0.0.1:1/"),
        )
        for url, expected in cases:
            with self.subTest(url=url):
                self.assertEqual(container_route.host_route(url), expected)

    def test_only_the_host_is_replaced(self):
        url = "http://host.docker.internal/host.docker.internal?next=http://host.docker.internal/"
        expected = "http://127.0.0.1/host.docker.internal?next=http://host.docker.internal/"
        self.assertEqual(container_route.host_route(url), expected)

    def test_loopback_urls_are_unchanged(self):
        for url in LOOPBACK_URLS:
            with self.subTest(url=url):
                self.assertEqual(container_route.host_route(url), url)

    def test_other_urls_are_unchanged(self):
        for url in OTHER_URLS:
            with self.subTest(url=url):
                self.assertEqual(container_route.host_route(url), url)

    def test_ipv6_literal_with_port_is_unchanged(self):
        for url in ("http://[::1]:8080/", "http://[2001:db8::1]:8080/x?y=1"):
            with self.subTest(url=url):
                self.assertEqual(container_route.host_route(url), url)

    def test_invalid_urls_raise_value_error(self):
        for url in INVALID_URLS:
            with self.subTest(url=url):
                with self.assertRaises(ValueError):
                    container_route.host_route(url)


if __name__ == "__main__":
    unittest.main()
