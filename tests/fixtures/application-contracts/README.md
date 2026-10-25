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

The three `historical-*.json` files are byte-for-byte archival copies from the
2026-10-07 evidence paths recorded in `historical_origin` in the baseline. The
sealed result is a blocked admission outcome; the experiment/matrix describe a
separate historical collection. No claim about new application-client or budget
capabilities follows from these archives. Paths and identities remain historical
source data, never executable instructions or current runtime selection.

The test suite verifies that the existing frozen-result reader still accepts the
sealed result, derives its unchanged outcome, rejects byte tampering and leaves
historical bytes untouched. Broader legacy experiment archive verification is
also covered by `tests/test_experiment_plan_identity.py`.
