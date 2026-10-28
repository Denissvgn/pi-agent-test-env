"""Create-only legacy owner publication under the original lease and held FDs."""
import copy
import contextlib
import hashlib
import os
from pathlib import Path
import stat
import uuid

import application_owner_cleanup as cleanup
import application_owner_legacy as legacy
import application_owner_legacy_discard as discard
import application_owner_legacy_native as native
import application_owner_legacy_protocol as protocol
import registry_maintenance as maintenance


def _now():
    return cleanup.controls.now().replace('+00:00', 'Z')


class _Directory:
    def __init__(self, receipt, owner, *, folders=(), output=False):
        self.receipt = receipt; self.owner = owner; self.folders = folders; self.output = output; self.files = {}

    @classmethod
    def open(cls, path, owner, attribute, *, folders=()):
        owner.verify()
        parent = cleanup.directory(path.parent); receipt = maintenance._Receipt(path, parent)
        try:
            receipt.parent_identity = maintenance._identity(os.fstat(parent))
            try:receipt.fd = os.open(path.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
            except FileNotFoundError:
                cleanup.require(getattr(owner.registry, attribute, None) is None, 'unsafe_path')
                owner.mutating()
                with cleanup.diagnostics.operation('directory_create', mutating=True):os.mkdir(path.name, 0o700, dir_fd=parent)
                with cleanup.diagnostics.operation('directory_fsync', mutating=True):os.fsync(parent)
                owner.verify()
                receipt.fd = os.open(path.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
            receipt.identity = maintenance._identity(os.fstat(receipt.fd))
            receipt.verify_namespace(); cleanup._bind_directory(owner.registry, attribute, receipt.fd)
            value = cls(receipt, owner, folders=folders); value.verify(); return value
        except BaseException:
            try:receipt.close()
            except BaseException:pass
            raise

    def verify(self, *, full=False, inventory=True):
        self.receipt.verify_namespace(); fd = self.receipt.fd; count = 0
        scan = os.open('.', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd) if inventory else None
        try:
            with (os.scandir(scan) if scan is not None else contextlib.nullcontext(())) as entries:
                for entry in entries:
                    count += 1
                    limit = 3 if self.output else cleanup.ownership.MAX_RECORDS + len(self.folders)
                    cleanup.require(count <= limit, 'inventory_unbounded')
                    info = os.stat(entry.name, dir_fd=fd, follow_symlinks=False)
                    cleanup.require(info.st_uid == os.getuid() and not stat.S_IMODE(info.st_mode) & 0o077, 'unsafe_path')
                    if entry.name in self.folders:cleanup.require(stat.S_ISDIR(info.st_mode)); continue
                    allowed = entry.name in ('intent.json', 'terminal.json', 'failure.json') if self.output else (
                        entry.name.endswith('.json') and cleanup.controls.valid_id(entry.name[:-5]))
                    cleanup.require(allowed and stat.S_ISREG(info.st_mode) and info.st_nlink == 1
                                    and info.st_size <= cleanup.MAX_BYTES, 'unsafe_record')
        finally:
            if scan is not None:os.close(scan)
        for name, (reference, signature) in self.files.items():
            info = os.stat(name, dir_fd=fd, follow_symlinks=False)
            cleanup.require(cleanup._purge_signature(info) == signature, 'owner_proof_publication_incomplete')
            if full:
                unused, observed = self.owner.reader.read(self.receipt.path / name, private=True, parent_fd=fd)
                cleanup.require(observed == reference)
        self.receipt.verify_namespace()

    def create(self, name, body, *, local=False):
        verify = self.verify if local else self.owner.verify
        verify(); wire = cleanup.canonical(body); cleanup.require(len(wire) <= cleanup.MAX_BYTES, 'inventory_unbounded')
        self.owner.mutating()
        with cleanup.diagnostics.operation('temporary_create', mutating=True):
            fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=self.receipt.fd)
        with os.fdopen(fd, 'wb') as output:
            with cleanup.diagnostics.operation('file_write', mutating=True):
                output.write(wire); output.flush()
            with cleanup.diagnostics.operation('file_fsync', mutating=True):os.fsync(output.fileno())
            info = os.fstat(output.fileno())
            cleanup.require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_uid == os.getuid()
                            and not stat.S_IMODE(info.st_mode) & 0o077, 'unsafe_record')
            signature = cleanup._purge_signature(info)
        reference = {'path': str(self.receipt.path / name), 'sha256': hashlib.sha256(wire).hexdigest()}
        self.files[name] = reference, signature
        verify()
        with cleanup.diagnostics.operation('directory_fsync', mutating=True):
            os.fsync(self.receipt.fd); os.fsync(self.receipt.parent)
        verify()
        if not local:
            unused, observed = self.owner.reader.read(reference['path'], private=True, parent_fd=self.receipt.fd)
            cleanup.require(observed == reference)
        return reference

    def remember(self, name, expected):
        unused, reference = self.owner.reader.read(self.receipt.path / name, private=True, parent_fd=self.receipt.fd)
        info = os.stat(name, dir_fd=self.receipt.fd, follow_symlinks=False)
        cleanup.require(reference == expected['reference'] and cleanup._purge_signature(info) == expected['signature'],
                        'owner_proof_publication_incomplete')
        self.files[name] = reference, cleanup._purge_signature(info)

    def close(self):self.receipt.close()


class _Publisher:
    def __init__(self, registry, reader):
        self.registry = registry; self.reader = reader; self.directories = []; self.output = None
        self.effects = 'none_observed'; self.intent = None; self.invocation = str(uuid.uuid4())

    def mutating(self):self.effects = 'may_have_occurred'

    def verify(self, *, full=False, inventory=True):
        native._lease(self.registry)
        for directory in self.directories:directory.verify(full=full, inventory=inventory)

    def guard(self):self.verify(inventory=False)

    def unselected(self, record):
        cleanup.require(record['launch_id'] not in getattr(self.registry, '_owner_proof_selected_ids', set()), 'owner_proof_publication_incomplete')
        cleanup.require(cleanup._read_anchor(self.registry, record, self.reader) is None, 'owner_proof_publication_incomplete')
        for path in (cleanup._index(self.registry, record), cleanup._selection(self.registry, record)):
            try:value, unused = self.reader.read(path, private=True)
            except FileNotFoundError:cleanup.require(not os.path.lexists(path))
            else:
                cleanup._remember_document_selection(self.registry, record, value)
                cleanup.require(False, 'owner_proof_publication_incomplete')

    def begin(self, operation, output_dir, runner):
        record = operation.observation['record']; plan = operation.observation['plan']
        target = Path(output_dir).expanduser().absolute()
        for excluded in (cleanup.store_path(self.registry), cleanup._anchor(self.registry, record).parent):
            cleanup.require(not discard._overlap(target.resolve(strict=False), excluded), 'unsafe_path')
        self.mutating()
        receipt = maintenance._new_receipt_directory(target, self.registry.root.with_name(self.registry.root.name[:-9]),
                                                       self.registry, self.registry.load())
        self.output = _Directory(receipt, self, output=True); self.directories.append(self.output)
        self.verify()
        with cleanup.diagnostics.operation('directory_fsync', mutating=True):
            os.fsync(receipt.parent); os.fsync(receipt.fd)
        self.verify()
        common = {'invocation_id': self.invocation, 'method': legacy.METHOD, 'cohort': legacy.COHORT,
            'variant': operation.request['variant'], 'started_at': _now(), 'subject': cleanup.subject(record),
            'lease': operation.observation['lease'], 'request': copy.deepcopy(operation.request),
            'metadata': copy.deepcopy(plan['metadata']), 'roots': copy.deepcopy(plan['roots']),
            'related_subjects': [cleanup._resource_subject(row) for row in operation.observation['related']],
            'runner_content_sha256': runner, 'admission_authorized': False, 'original_outcome_regraded': False,
            'new_containers': 0, 'participant_stages': 0, 'model_requests': 0}
        self.common = common
        self.intent = self.output.create('intent.json', {'schema': 1, 'document_type': 'application_owner_cleanup_intent',
                                                       'status': 'RUNNING', **common})
        self.store = _Directory.open(cleanup.store_path(self.registry), self, '_owner_proof_store_identity', folders=('selected', 'custody'))
        self.directories.append(self.store)
        self.anchor = _Directory.open(cleanup._anchor(self.registry, record).parent, self, '_owner_anchor_identity')
        self.directories.append(self.anchor)
        cleanup._remember_legacy_selection(self.registry, record)
        self.anchor.create(record['launch_id'] + '.json', {'schema': 1, 'document_type': 'application_owner_cleanup_anchor',
            'subject': common['subject'], 'method': legacy.METHOD, 'cohort': legacy.COHORT, 'intent': self.intent})
        self.selected = _Directory.open(cleanup._selection(self.registry, record).parent, self, '_owner_selected_identity')
        self.directories.append(self.selected)
        self.selected.create(record['launch_id'] + '.json', {'schema': 2, 'document_type': 'application_owner_cleanup_selection',
            'subject': common['subject'], 'method': legacy.METHOD, 'cohort': legacy.COHORT})
        self.verify(full=True)
        # Reserve the two remaining mandatory documents before payload effects.
        terminal = self.terminal('9999-12-31T23:59:59.999999Z')
        reference = {'path': str(self.output.receipt.path / 'terminal.json'), 'sha256': '0' * 64}
        index = {'schema': 2, 'document_type': 'application_owner_cleanup_index', 'subject': common['subject'],
                 'method': legacy.METHOD, 'cohort': legacy.COHORT, 'receipt': reference}
        sizes = [len(cleanup.canonical(value)) for value in (terminal, index)]
        cleanup.require(len(self.reader.references) + 2 <= cleanup.MAX_REFERENCES and max(sizes) <= cleanup.MAX_BYTES
                        and self.reader.bytes + sum(sizes) <= cleanup.MAX_AGGREGATE_BYTES, 'inventory_unbounded')

    def terminal(self, finished):
        return {'schema': 2, 'document_type': 'application_owner_cleanup_receipt', 'status': 'CLEANED', **self.common,
            'finished_at': finished, 'cleanup_completed': True, 'scope': 'owned_host_files_only',
            'global_actor_census': 'not_attested', 'credential_memory_erasure': 'not_attested',
            'effects': 'may_have_occurred', 'evidence_sha256': self.common['request']['evidence']['sha256'], 'intent': self.intent}

    def failure(self, error):
        if self.output is None:return
        try:
            trusted = error if isinstance(error, cleanup.ownership.RegistryError) else cleanup.ownership.RegistryError(
                'Owner publication did not complete', condition='owner_proof_publication_incomplete', cause=error)
            diagnostic = cleanup.diagnostics.diagnostic(trusted)
            if self.effects == 'may_have_occurred':diagnostic['effects'] = self.effects
            self.output.create('failure.json', {'schema': 1, 'document_type': 'application_owner_cleanup_failure',
                'invocation_id': self.invocation, 'intent': self.intent,
                'status': 'INTERRUPTED' if isinstance(error, KeyboardInterrupt) else 'BLOCKED', 'finished_at': _now(),
                'diagnostic': diagnostic, 'effects': self.effects, 'cleanup_completed': False, 'admission_authorized': False}, local=True)
        except BaseException:pass

    def close(self):
        errors = []
        for directory in reversed(self.directories):
            try:directory.close()
            except OSError as error:errors.append(error)
        self.directories.clear()
        if errors:raise errors[0]


@cleanup.diagnostics.scoped('owner_legacy_publication', 'owner_proof_publication_incomplete')
def recover(registry, request, output_dir, *, discard_workspace=False, reader=None):
    cleanup.require(discard_workspace is True, 'owner_discard_required')
    reader = cleanup.Reader() if reader is None else reader
    native._lease(registry); record, unused, unused = protocol._plan(registry, request, reader)
    publisher = _Publisher(registry, reader); primary = None
    try:
        publisher.unselected(record)
        runner = maintenance._runner_identity()
        with discard._BoundCleanup(registry, request, discard_workspace=True, reader=reader) as operation:
            publisher.begin(operation, output_dir, runner)
            operation.purge(publication_guard=publisher.guard)
        publisher.verify(full=True)
        cleanup.require(maintenance._runner_identity() == runner)
        report = publisher.terminal(_now())
        reference = publisher.output.create('terminal.json', report)
        publisher.verify(full=True)
        written = cleanup._publish_index(registry, record, reference, method=legacy.METHOD, cohort=legacy.COHORT)
        publisher.store.remember(record['launch_id'] + '.json', written); publisher.verify(full=True)
        cleanup.require(cleanup.validate_accepted(registry, record), 'owner_proof_publication_incomplete')
        return {**report, 'receipt_persistence': 'confirmed'}
    except BaseException as error:
        primary = error; publisher.failure(error); raise
    finally:
        try:publisher.close()
        except BaseException:
            if primary is None:raise
