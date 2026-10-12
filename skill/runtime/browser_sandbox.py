"""Parse Chromium's own diagnostic table; command-line intent alone is insufficient."""
from html.parser import HTMLParser


class SandboxTable(HTMLParser):
    def __init__(self):
        super().__init__(); self.inside = False; self.cell = None; self.row = []; self.rows = {}

    def handle_starttag(self, tag, attrs):
        if tag == 'table' and dict(attrs).get('id') == 'sandbox-status': self.inside = True
        if self.inside and tag == 'tr': self.row = []
        if self.inside and tag == 'td': self.cell = ''

    def handle_data(self, data):
        if self.cell is not None: self.cell += data

    def handle_endtag(self, tag):
        if tag == 'td' and self.cell is not None: self.row.append(self.cell.strip()); self.cell = None
        if tag == 'tr' and self.inside and len(self.row) == 2:
            if self.row[0] in self.rows: raise ValueError('Duplicate sandbox diagnostic row')
            self.rows[self.row[0]] = self.row[1]
        if tag == 'table': self.inside = False


def observed(html):
    table = SandboxTable(); table.feed(html)
    rows = table.rows
    verified = (rows.get('Layer 1 Sandbox') == 'Namespace' and
                all(rows.get(name) == 'Yes' for name in ('PID namespaces', 'Network namespaces', 'Seccomp-BPF sandbox')))
    return {'origin': 'Chromium chrome://sandbox', 'rows': rows, 'namespace_and_seccomp_verified': verified}
