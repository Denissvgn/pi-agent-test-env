# Check file for container_route.classify and container_route.host_route. This
# header is the whole specification.
#
#     classify(url)    -> 'loopback' | 'docker-host' | 'other'
#     host_route(url)  -> str
#
# Specification
#   classify(url) returns 'loopback' for the hosts localhost, 0.0.0.0, ::1 and
#   any address in 127.0.0.0/8, 'docker-host' for host.docker.internal and
#   gateway.docker.internal, and 'other' otherwise; a URL without an http or
#   https scheme or without a host raises ValueError.
#   host_route(url) returns the URL with the host replaced by 127.0.0.1 when its
#   class is docker-host, keeping scheme, port, path and query, and returns it
#   unchanged otherwise.
#
# How the checks read it
#   - The host is the name or address of the authority, without any port. An
#     IPv6 literal is written in brackets and the brackets are not part of the
#     host: in 'http://[::1]:8080/x' the host is ::1 and the port is 8080.
#   - 127.0.0.0/8 runs from 127.0.0.0 to 127.255.255.255. Only 0.0.0.0 itself is
#     loopback among the 0.x.x.x addresses, and only ::1 among the IPv6 ones, so
#     0.0.0.1 and :: are 'other'.
#   - The names are matched as whole hosts. A name that only contains or ends in
#     one of them (localhost.example.com, host.docker.internal.example.com) is
#     'other', and a special name in the path or the query does not count.
#   - The port, path and query never change the class.
#   - A URL that host_route rewrites differs from the original only in the host.
#     That includes a URL with no path: its path stays empty and no '/' is added.
#   - Both functions return a string. Any str subclass will do.
#   - host_route validates exactly like classify.
#
# Not specified, so not checked: the case of the scheme or the host, user
# information before the host, fragments, an empty query marker ('?' with
# nothing after it), percent-encoding, trailing dots in host names, shorthand IPv4 forms such as 127.1, IPv4-mapped IPv6 addresses, zone
# identifiers and invalid ports.
#
# The file runs in the repository and, unchanged, in a scratch project: it
# puts skill/scripts (when present) and the working directory on the import
# path, and it is skipped while container_route does not exist.
import sys
import unittest
from pathlib import Path
from urllib.parse import urlsplit

for _dir in (Path(__file__).resolve().parents[1]/'skill'/'scripts',
             Path.cwd()/'skill'/'scripts', Path.cwd()):
    if _dir.is_dir() and str(_dir) not in sys.path:
        sys.path.insert(0, str(_dir))
try:
    import container_route
except ModuleNotFoundError as exc:
    if exc.name != 'container_route':
        raise
    container_route = None


def classify(url):
    return container_route.classify(url)


def host_route(url):
    return container_route.host_route(url)


class ContainerRouteTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if container_route is None:
            raise unittest.SkipTest('module not present')

    def assertClass(self, expected, urls):
        for url in urls:
            with self.subTest(url=url):
                result = classify(url)
                self.assertIsInstance(result, str)
                self.assertEqual(result, expected)

    # classify: loopback

    def test_loopback_names_and_addresses(self):
        self.assertClass('loopback', [
            'http://localhost/', 'http://0.0.0.0/', 'http://127.0.0.1/', 'http://[::1]/',
            'https://localhost/', 'https://127.0.0.1/', 'http://localhost:8080/v1?x=1'])

    def test_loopback_covers_the_whole_127_block(self):
        self.assertClass('loopback', [
            'http://127.0.0.0/', 'http://127.0.0.2/', 'http://127.1.2.3/',
            'http://127.255.255.254/', 'http://127.255.255.255/'])

    def test_addresses_next_to_the_127_block_are_other(self):
        self.assertClass('other', [
            'http://126.255.255.255/', 'http://128.0.0.0/', 'http://128.0.0.1/',
            'http://0.0.0.1/', 'http://127.0.0.1.example.com/'])

    def test_ipv6_literals_with_and_without_ports(self):
        self.assertClass('loopback', [
            'http://[::1]/', 'http://[::1]:8080/', 'http://[::1]:80/v1/x?y=1', 'https://[::1]:443'])
        self.assertClass('other', [
            'http://[::]/', 'http://[::]:8080/', 'http://[2001:db8::1]/',
            'http://[2001:db8::1]:8080/', 'http://[::2]:8080/'])

    # classify: docker-host

    def test_docker_host_names(self):
        self.assertClass('docker-host', [
            'http://host.docker.internal/', 'https://host.docker.internal/',
            'http://gateway.docker.internal/', 'https://gateway.docker.internal/'])

    def test_docker_host_with_ports_paths_and_queries(self):
        self.assertClass('docker-host', [
            'http://host.docker.internal:11434/v1/chat?stream=1',
            'http://gateway.docker.internal:8080', 'http://host.docker.internal?x=1'])

    # classify: other

    def test_other_hosts(self):
        self.assertClass('other', [
            'http://example.com/', 'https://api.example.com:8443/v1', 'http://10.0.0.5/',
            'http://192.168.1.10:8080/', 'http://172.17.0.1/', 'http://docker.internal/'])

    def test_names_that_only_look_like_special_hosts_are_other(self):
        self.assertClass('other', [
            'http://localhost.example.com/', 'http://foo.localhost/', 'http://localhost2/',
            'http://host.docker.internal.example.com/', 'http://myhost.docker.internal/',
            'http://gateway.docker.internal.evil.test/'])

    def test_special_names_in_the_path_or_query_do_not_count(self):
        self.assertClass('other', [
            'http://example.com/localhost', 'http://example.com/?h=host.docker.internal',
            'http://example.com:80/http://127.0.0.1/'])

    # classify and host_route: invalid URLs

    INVALID = [
        '', 'localhost', 'localhost:8080/x', '//localhost/x', '/path/only',
        'ftp://localhost/', 'file:///etc/hosts',
        'http://', 'https://', 'http:///x', 'https:///', 'http://:8080/', 'https://:443/x']

    def test_invalid_urls_raise_value_error_in_classify(self):
        for url in self.INVALID:
            with self.subTest(url=url):
                with self.assertRaises(ValueError):
                    classify(url)

    def test_invalid_urls_raise_value_error_in_host_route(self):
        for url in self.INVALID:
            with self.subTest(url=url):
                with self.assertRaises(ValueError):
                    host_route(url)

    # host_route: docker-host is rewritten

    def test_docker_host_is_replaced_by_the_ipv4_loopback(self):
        self.assertEqual(host_route('http://host.docker.internal/'), 'http://127.0.0.1/')
        self.assertEqual(host_route('https://gateway.docker.internal/'), 'https://127.0.0.1/')

    def test_scheme_port_path_and_query_are_kept(self):
        self.assertEqual(
            host_route('http://host.docker.internal:11434/v1/chat/completions?stream=true&n=2'),
            'http://127.0.0.1:11434/v1/chat/completions?stream=true&n=2')
        self.assertEqual(host_route('https://gateway.docker.internal:8443/a/b/?q=1'),
                         'https://127.0.0.1:8443/a/b/?q=1')
        self.assertEqual(host_route('http://gateway.docker.internal/v1'), 'http://127.0.0.1/v1')

    def test_a_bare_docker_host_url_keeps_scheme_port_empty_path_and_query(self):
        result = host_route('https://gateway.docker.internal:8443?q=1')
        self.assertEqual(result, 'https://127.0.0.1:8443?q=1')
        parts = urlsplit(result)
        self.assertEqual((parts.scheme, parts.hostname, parts.port, parts.path, parts.query),
                         ('https', '127.0.0.1', 8443, '', 'q=1'))

    def test_only_the_host_is_replaced(self):
        url = 'http://host.docker.internal/path/host.docker.internal?h=host.docker.internal'
        self.assertEqual(host_route(url),
                         'http://127.0.0.1/path/host.docker.internal?h=host.docker.internal')

    # host_route: everything else is unchanged

    def test_loopback_urls_are_unchanged(self):
        for url in ('http://localhost:8080/v1?x=1', 'http://127.0.0.1/', 'https://127.1.2.3:8443/a',
                    'http://0.0.0.0:9000/', 'http://[::1]:8080/x', 'http://[::1]/'):
            with self.subTest(url=url):
                self.assertEqual(host_route(url), url)

    def test_other_urls_are_unchanged(self):
        for url in ('http://example.com/', 'https://api.example.com:8443/v1?x=1',
                    'http://10.0.0.5:80/', 'http://[2001:db8::1]:8080/x',
                    'http://localhost.example.com/', 'http://host.docker.internal.example.com/x',
                    'http://example.com/?h=host.docker.internal'):
            with self.subTest(url=url):
                self.assertEqual(host_route(url), url)

    def test_host_route_returns_a_string(self):
        for url in ('http://host.docker.internal/', 'http://localhost/', 'http://example.com/'):
            with self.subTest(url=url):
                self.assertIsInstance(host_route(url), str)


if __name__ == '__main__':
    unittest.main()
