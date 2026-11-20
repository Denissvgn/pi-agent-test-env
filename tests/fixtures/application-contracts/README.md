# A01 independent contract and compatibility fixtures

`positive.json` freezes the synthetic source, report, receipt and artifact shapes
from the reviewed planning contract. It is deliberately independent of the
production validators and compiler. Its image ID, request receipts and identities
are examples only; it is not an executable plan or evidence of a new invocation.

`completion.json` retains the independent completion fixture with its synthetic
raw captures and expected diagnostic projection. These maintainer fixtures travel
with the source archive; tests do not depend on the internal planning directory.

`legacy-baseline.json` records hashes obtained before A01 production changes on
2026-10-17. Its release identities, raw release-contract bytes, existing profile
asset bytes and profile identities protect both reviewed releases. Its explicit
legacy schema-1 and schema-2 normalization outputs protect existing defaults and
the absence of application/reporting fields. Tests do not update these goldens.

The three `historical-*.json` fixtures retain the historical experiment, matrix
and sealed result formats. The experiment and result use synthetic paths. The
baseline pins the checked-in fixture bytes. The sealed result records a blocked
admission, and the experiment and matrix describe a separate collection.

The test suite verifies that the existing frozen-result reader still accepts the
sealed result, derives its unchanged outcome, rejects byte tampering and leaves
the fixture bytes untouched. Broader legacy experiment archive verification is
also covered by `tests/test_experiment_plan_identity.py`.
