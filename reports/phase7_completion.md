# Phase 7 — Threat Hunting

## Status
COMPLETE — Both hunt reports include required sections, event-level timestamps, source-file references, findings, conclusions, detection improvements, and documented evidence limitations.

## Hunt Reports
1. `hunts/hunt_01_powershell_lsass_correlation.md`
2. `hunts/hunt_02_failed_logon_followed_by_success.md`

## Evidence Summary
- PowerShell-to-LSASS correlation: 3 matching sequences within 10 minutes.
- Failed-logon-to-successful-logon correlation: 2 matching sequences within 15 minutes.
- Failed-logon burst: implemented but not demonstrated in the available validation run.

## Interpretation
These results represent matches in a sample dataset. They do not establish confirmed malicious activity or a real-world incident. The failed-logon correlation may pair one failed event with multiple successful events, so sequence counts must not be treated as independent attack counts.

## Remaining Validation
- Review individual event timestamps, host and user context, process details, and source addresses where available.
- Confirm that each hunt's evidence can be traced to the underlying events or validation output.
- Add further hunts only when supported by available telemetry.

## Scope
No live environment was queried, and no dataset or detection rule was modified as part of documenting these hunts.

## Event-Level Verification Addendum

The existing Phase 5 validation logic was reused to inspect individual matching records.

- **Hunt 1:** Three PowerShell-to-LSASS sequences were inspected. Their observed time differences were 76.6, 126.4 and 327.4 seconds.
- **Hunt 2:** One failed logon for `IEUser` was followed by two successful-logon records approximately 4.1 seconds later in the same EVTX file.
- The second hunt's two matches share the same failed event; they are not two independent failed attempts.
- The extracted host field was empty, and some identity/authentication context remains unavailable. These limitations are recorded in the individual hunt reports.

## Final Interpretation

Both hunts now include event-level timestamps and source-file references. Findings remain investigation leads rather than confirmed incidents. Detection improvements and remaining telemetry limitations are documented in each report.

No live environment was queried, and no detection rules were changed by this evidence review.
