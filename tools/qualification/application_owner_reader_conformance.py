"""Portable SDK gate model for synthetic conformance, never qualification authority.

Only standard-library code loads here. A downstream SDK must obtain support and
provider approval from its own trusted policy before importing provider code.
Vectors, manifests, hashes and this gate model cannot grant that approval.
"""
import re

CONTRACT = 'application_owner_legacy_reader_1'
SCOPE = 'owned_host_files_only'


def gate(policy, observed_provider, scope, variant='standard_workspace_v1'):
    """Model an already trusted consumer policy; fail before a reader callback."""
    if type(policy) is not dict or set(policy) != {'schema', 'contracts', 'approved_provider', 'scopes', 'variants'}:return False
    if type(policy['schema']) is not int or policy['schema'] != 1:return False
    for field in ('contracts', 'scopes', 'variants'):
        values = policy[field]
        if type(values) is not list or len(values) > 16:return False
        if any(type(value) is not str or not 1 <= len(value) <= 128 for value in values):return False
        if values != sorted(set(values)):return False
    provider = policy['approved_provider']
    if type(provider) is not str or re.fullmatch('[a-f0-9]{64}', provider) is None or provider == '0' * 64:return False
    return (CONTRACT in policy['contracts'] and scope == SCOPE and scope in policy['scopes']
            and type(observed_provider) is str and observed_provider == provider
            and variant in ('standard_workspace_v1', 'diagnostic_disposable_v1') and variant in policy['variants'])


def replay(policy, observed_provider, scope, reader, *, variant='standard_workspace_v1'):
    """Run only a caller-approved reader; this model performs no file/native IO."""
    if not gate(policy, observed_provider, scope, variant):return 'extension_required'
    try:result = reader()
    except (OSError, ValueError):return 'invalid_proof'
    if result is True:return 'proof_accepted'
    if result is False:return 'not_selected'
    return 'invalid_proof'
