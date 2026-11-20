# Check file for container_route.classify and container_route.host_route. This
# header is the whole specification.
#
#     classify(url)    -> 'loopback' | 'docker-host' | 'other'
#     host_route(url)  -> str
#
# Both take one URL string. A URL is valid only when its scheme is http or
# https (the scheme is case-insensitive) and it has a host. Anything else
# raises ValueError: no scheme ('localhost:8080/x', '//localhost/x', ''), a
# scheme other than http or https ('ftp://localhost/'), or no host ('http://',
# 'http:///x', 'https://:8080/'). host_route validates exactly like classify.
#
# The host is the part of the authority after any 'user@' and before any ':port'.
# An IPv6 literal is written in brackets and its brackets are not part of the
# host: in 'http://[::1]:8080/x' the host is ::1 and the port is 8080.
#
# classify rules, on the host. Host names are compared case-insensitively.
#   'loopback'     localhost, 0.0.0.0, ::1, and every IPv4 address in
#                  127.0.0.0/8 (127.0.0.0 to 127.255.255.255).
#   'docker-host'  host.docker.internal and gateway.docker.internal.
#   'other'        everything else. That includes names that merely contain or
#                  end in one of the names above (localhost.example.com,
#                  foo.localhost, host.docker.internal.example.com), the IPv6
#                  address :: (only ::1 is loopback), 0.0.0.1, 126.255.255.255,
#                  128.0.0.1 and any other address.
#   The port, path, query and userinfo never change the class.
#
# host_route rules.
#   - When the class is 'docker-host', the result is the URL with only the host
#     text replaced by 127.0.0.1. Everything else stays exactly as written:
#     the scheme, userinfo, port, path, query (including an empty '?') and
#     fragment, byte for byte.
#   - In every other case ('loopback' or 'other') the URL is returned unchanged,
#     as the same text, whatever its case.
#
# Not specified, so not checked: trailing dots in host names, shorthand IPv4
# forms such as 127.1, IPv4-mapped IPv6 addresses, zone identifiers, invalid
# ports, and the case of the scheme in a rewritten URL.
#
# Boundaries covered below: the edges of 127.0.0.0/8, bracketed IPv6 with and
# without ports, hosts that only look like the special names, mixed-case hosts,
# missing port, empty path, and query and fragment retention.
#
# The file runs in the repository and, unchanged, in a scratch project: it
# puts skill/scripts (when present) and the working directory on the import
# path, and it is skipped while container_route does not exist.
import sys
import unittest
from pathlib import Path

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
                self.assertEqual(classify(url), expected)

    # classify: loopback

    def test_loopback_names_and_addresses(self):
        self.assertClass('loopback', [
            'http://localhost/', 'http://0.0.0.0/', 'http://127.0.0.1/',
            'http://[::1]/', 'https://localhost/', 'https://127.0.0.1/'])

    def test_loopback_covers_the_whole_127_block(self):
        self.assertClass('loopback', [
            'http://127.0.0.0/', 'http://127.0.0.2/', 'http://127.1.2.3/',
            'http://127.255.255.254/', 'http://127.255.255.255/'])

    def test_addresses_next_to_the_127_block_are_other(self):
        self.assertClass('other', [
            'http://126.255.255.255/', 'http://128.0.0.0/', 'http://128.0.0.1/',
            'http://12.7.0.1/', 'http://127.0.0.1.example.com/'])

    def test_only_the_zero_address_itself_is_loopback_among_zero_networks(self):
        self.assertClass('other', ['http://0.0.0.1/', 'http://0.0.0.2/', 'http://1.0.0.0/'])

    def test_ipv6_literals_with_and_without_ports(self):
        self.assertClass('loopback', [
            'http://[::1]/', 'http://[::1]:8080/', 'http://[::1]:80/v1/x?y=1',
            'https://[::1]:443'])

    def test_other_ipv6_literals_are_other(self):
        self.assertClass('other', [
            'http://[::]/', 'http://[::]:8080/', 'http://[::2]/', 'http://[::2]:8080/',
            'http://[2001:db8::1]/', 'http://[2001:db8::1]:8080/', 'http://[fe80::1]:9/'])

    def test_host_names_are_case_insensitive(self):
        self.assertClass('loopback', ['http://LOCALHOST/', 'http://LocalHost:80/'])
        self.assertClass('docker-host', [
            'http://Host.Docker.Internal/', 'http://GATEWAY.DOCKER.INTERNAL:8080/'])

    def test_scheme_is_case_insensitive(self):
        self.assertClass('loopback', ['HTTP://localhost/', 'Https://127.0.0.1:8443/'])

    # classify: docker-host

    def test_docker_host_names(self):
        self.assertClass('docker-host', [
            'http://host.docker.internal/', 'https://host.docker.internal/',
            'http://gateway.docker.internal/', 'https://gateway.docker.internal/'])

    def test_docker_host_with_ports_paths_and_queries(self):
        self.assertClass('docker-host', [
            'http://host.docker.internal:11434/v1/chat?stream=1',
            'http://gateway.docker.internal:8080',
            'http://host.docker.internal?x=1', 'http://host.docker.internal/#frag'])

    def test_userinfo_does_not_change_the_host(self):
        self.assertClass('loopback', ['http://user:pass@localhost:8080/x', 'http://user@127.0.0.1/'])
        self.assertClass('docker-host', ['http://user:pass@host.docker.internal:80/'])
        self.assertClass('other', ['http://localhost:pass@example.com/', 'http://localhost@example.com/'])

    # classify: other

    def test_other_hosts(self):
        self.assertClass('other', [
            'http://example.com/', 'https://api.example.com:8443/v1', 'http://10.0.0.5/',
            'http://192.168.1.10:8080/', 'http://172.17.0.1/', 'http://docker.internal/',
            'http://internal/'])

    def test_names_that_only_look_like_special_hosts_are_other(self):
        self.assertClass('other', [
            'http://localhost.example.com/', 'http://foo.localhost/', 'http://notlocalhost/',
            'http://localhost2/', 'http://host.docker.internal.example.com/',
            'http://myhost.docker.internal/', 'http://host.docker.internal2/',
            'http://gateway.docker.internal.evil.test/', 'http://docker-host/'])

    def test_special_names_in_the_path_or_query_do_not_count(self):
        self.assertClass('other', [
            'http://example.com/localhost', 'http://example.com/?h=host.docker.internal',
            'http://example.com/#127.0.0.1', 'http://example.com:80/http://localhost/'])

    def test_result_is_a_plain_string(self):
        self.assertIs(type(classify('http://localhost/')), str)
        self.assertIs(type(classify('http://example.com/')), str)

    # classify and host_route: invalid URLs

    INVALID = [
        '', 'localhost', 'localhost:8080/x', '//localhost/x', '/path/only', 'host.docker.internal',
        'ftp://localhost/', 'file:///etc/hosts', 'ws://localhost/', 'unix:///tmp/x',
        'http://', 'https://', 'http:///x', 'https:///', 'http://:8080/', 'https://:443/x',
        'http://user@/x', 'http:localhost', 'mailto:someone']

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

    def test_port_path_and_query_are_kept(self):
        self.assertEqual(
            host_route('http://host.docker.internal:11434/v1/chat/completions?stream=true&n=2'),
            'http://127.0.0.1:11434/v1/chat/completions?stream=true&n=2')
        self.assertEqual(
            host_route('https://gateway.docker.internal:8443/a/b%20c/?q=%2F&r='),
            'https://127.0.0.1:8443/a/b%20c/?q=%2F&r=')

    def test_missing_port_and_empty_path(self):
        self.assertEqual(host_route('http://host.docker.internal'), 'http://127.0.0.1')
        self.assertEqual(host_route('http://host.docker.internal:9000'), 'http://127.0.0.1:9000')
        self.assertEqual(host_route('http://host.docker.internal?x=1'), 'http://127.0.0.1?x=1')
        self.assertEqual(host_route('https://gateway.docker.internal/'), 'https://127.0.0.1/')

    def test_empty_query_marker_and_fragment_are_kept(self):
        self.assertEqual(host_route('http://host.docker.internal/x?'), 'http://127.0.0.1/x?')
        self.assertEqual(host_route('http://host.docker.internal/x#top'), 'http://127.0.0.1/x#top')
        self.assertEqual(host_route('http://host.docker.internal/x?a=1#top'),
                         'http://127.0.0.1/x?a=1#top')

    def test_userinfo_is_kept(self):
        self.assertEqual(host_route('http://user:secret@host.docker.internal:80/x'),
                         'http://user:secret@127.0.0.1:80/x')

    def test_mixed_case_docker_host_is_rewritten(self):
        self.assertEqual(host_route('http://Host.Docker.Internal:8080/v1'), 'http://127.0.0.1:8080/v1')
        self.assertEqual(host_route('https://GATEWAY.DOCKER.INTERNAL/'), 'https://127.0.0.1/')

    def test_only_the_host_is_replaced(self):
        url = 'http://host.docker.internal/path/host.docker.internal?h=host.docker.internal'
        self.assertEqual(host_route(url),
                         'http://127.0.0.1/path/host.docker.internal?h=host.docker.internal')

    def test_rewritten_url_classifies_as_loopback(self):
        for url in ('http://host.docker.internal:8080/x', 'https://gateway.docker.internal/'):
            with self.subTest(url=url):
                self.assertEqual(classify(host_route(url)), 'loopback')

    def test_host_route_is_idempotent(self):
        once = host_route('http://host.docker.internal:8080/x?y=1')
        self.assertEqual(host_route(once), once)

    # host_route: everything else is unchanged

    def test_loopback_urls_are_unchanged(self):
        for url in ('http://localhost:8080/v1?x=1', 'http://127.0.0.1/', 'https://127.1.2.3:8443/a',
                    'http://0.0.0.0:9000', 'http://[::1]:8080/x', 'http://[::1]/',
                    'HTTP://LOCALHOST:80/Path'):
            with self.subTest(url=url):
                self.assertEqual(host_route(url), url)

    def test_other_urls_are_unchanged(self):
        for url in ('http://example.com/', 'https://api.example.com:8443/v1?x=1#f', 'http://10.0.0.5:80',
                    'http://[2001:db8::1]:8080/x', 'http://localhost.example.com/',
                    'http://host.docker.internal.example.com/x', 'http://example.com/?h=host.docker.internal',
                    'http://user@example.com:81/x?'):
            with self.subTest(url=url):
                self.assertEqual(host_route(url), url)

    def test_result_is_a_string(self):
        self.assertIs(type(host_route('http://host.docker.internal/')), str)
        self.assertIs(type(host_route('http://example.com/')), str)


if __name__ == '__main__':
    unittest.main()
