"""Reviewed immutable producer identities and their closed semantic rules.

Hashes identify code, not credentials or task outcomes. Source bytes are supplied
as bounded evidence and never executed. No external source catalog is accepted.
"""

ARTIFACT_PRODUCER = 'a5e36e9b679780819372bd2ec9b65e1737d6acbe6339582bd9c38021116ecf30'


def source_families():
    """Return independent data so callers cannot mutate the installed template."""
    return {ARTIFACT_PRODUCER: {
        'family_id': 'artifact_diagnostic_v1',
        'binding_format': 'artifact_diagnostic_v1',
        'variants': ('diagnostic_disposable_v1',),
        'supervisor_sha256': 'db1d1c987514be784e1eea86cb6e0eaf4082f8a991ffea18fa3a1a7c143eec82',
        'host_source_pins_sha256': '98da49a956058c9be2c866768c594037b14d3a0364bdeb8b6dab8beead2ad8c6',
        'runtime_source_pins_sha256': '06c9b325ee8a29735053cb5c1da2e780290c5666d8d16944026a9d3ff22f5084',
        'probe_sha256': 'bd09ee47fc3032aaf75d4831f8fdcda0a1f5cefe352ea842c99a790e7f5b908d',
        'prior_validator_sha256': 'd978a0a2f3d50324b8ebf32ed1266c84673cf27b264e4cad2e87994352847f62',
        'execution_rule': 'absolute_owned_host_paths_v1',
        'public_source_roles': ('producer', 'emitter', 'supervisor', 'probe', 'prior_validator'),
        'readable_metadata_parent_roles': ('inputs', 'source_binding', 'authority'),
    }}
