#!/usr/bin/env python3
"""Require named Go tests to execute successfully in a `go test -json` stream."""

import argparse
import json
import sys


API_PACKAGE = "github.com/feirai/averin/server/internal/api"
STORE_PACKAGE = "github.com/feirai/averin/server/internal/store"
PGSCHEMA_PACKAGE = "github.com/feirai/averin/server/internal/pgschema"
PGLEDGER_PACKAGE = "github.com/feirai/averin/server/internal/pgledger"
RESOURCESHIM_PACKAGE = "github.com/feirai/averin/server/internal/resourceshim"
REQUIRED = (
    f"{API_PACKAGE}:TestTenantNonceOfflineProjectComposition",
    f"{API_PACKAGE}:TestBrokerSeqVoidPostgres",
    f"{API_PACKAGE}:TestBrokerSeqVoidGrantLandsFirstPostgres",
    f"{API_PACKAGE}:TestBrokerSeqVoidGrantRollsBackPostgres",
    f"{API_PACKAGE}:TestBrokerSeqVoidMarkerFailsPostgres",
    f"{API_PACKAGE}:TestVoidWithoutRevocationKeyBlocksPreparedCapability",
    f"{API_PACKAGE}:TestBrokerSeqRecoveryPreflightReadOnly",
    f"{API_PACKAGE}:TestBrokerSeqRecoveryDeniedPostgres",
    f"{API_PACKAGE}:TestBrokerSeqRecoveryPerpetualFailedRetries",
    f"{API_PACKAGE}:TestBrokerSeqRecoveryLegacyTombstoneAttribution",
    f"{API_PACKAGE}:TestBrokerSeqRecoveryFencePersistsAcrossReplicasPostgres",
    f"{API_PACKAGE}:TestBrokerSeqRecoveryTerminalVoidBlocksUsePostgres",
    f"{API_PACKAGE}:TestBrokerSeqRecoveryCancelThenGrantCommitsPostgres",
    f"{API_PACKAGE}:TestBrokerSeqRecoveryProcessCrashCutsPostgres",
    f"{API_PACKAGE}:TestBrokerSeqRecoveryBlockedGuardDeadlinePostgres",
    f"{STORE_PACKAGE}:TestPostgresRecoveryFenceContract",
    f"{STORE_PACKAGE}:TestBrokerSeqRecoveryOldRuntimeCredentialCutoff",
    f"{PGSCHEMA_PACKAGE}:TestTenantNonceCutoverV3V4V5PreservesUnknownOwners",
    f"{PGSCHEMA_PACKAGE}:TestTenantNonceCutoverInterruptedBeforeCommitRetriesOnce",
    f"{PGSCHEMA_PACKAGE}:TestTenantNonceCutoverRejectsLiveAndInheritedOldWriter",
    f"{PGSCHEMA_PACKAGE}:TestTenantNonceRuntimeReadinessRequiresLeastPrivilege",
    f"{PGSCHEMA_PACKAGE}:TestTenantNonceLegacyPurgeRequiresDBTimeHold",
    f"{PGSCHEMA_PACKAGE}:TestTenantNonceOrdinaryStartupRefusesEmptyLegacyVersionTable",
    f"{STORE_PACKAGE}:TestPostgresScopedNonceClaimsAndOwnedRollback",
    f"{STORE_PACKAGE}:TestPostgresIndependentPoolsNonceRace",
    f"{STORE_PACKAGE}:TestPostgresLegacyGlobalExclusionsUntilDBCutoff",
    f"{STORE_PACKAGE}:TestPostgresMissingCutoverMetadataRejectsClaims",
    f"{PGLEDGER_PACKAGE}:TestPostgresLedgerMaintenance",
    f"{PGLEDGER_PACKAGE}:TestSweepFailureRetainsClaims",
    f"{RESOURCESHIM_PACKAGE}:TestAcceptedCapabilityLifetimeBoundsBeforeLedger",
    # Plan 009: temporal revocation ordering on real Postgres.
    f"{API_PACKAGE}:TestTemporalRevokeRacesUseAcrossPoolsPostgres",
    f"{API_PACKAGE}:TestTemporalCausalRevokeUseSchedulesPostgres",
    f"{API_PACKAGE}:TestTemporalRepeatedRevokeAcrossPoolsPostgres",
    f"{API_PACKAGE}:TestTemporalSnapshotExportConsistencyPostgres",
    f"{API_PACKAGE}:TestTemporalRevocationProcessCrashCutsPostgres",
    f"{API_PACKAGE}:TestTemporalConflictsBurnNoOrdinalPostgres",
    f"{PGSCHEMA_PACKAGE}:TestTemporalRevocationCutoverRefusesLiveNewRuntimeSession",
    f"{STORE_PACKAGE}:TestPostgresTemporalRevocationContract",
    f"{PGSCHEMA_PACKAGE}:TestTemporalRevocationCutoverFromV6",
    f"{PGSCHEMA_PACKAGE}:TestTemporalRevocationCutoverInterruptedRollsBackAndRetries",
    # Plan 007 project transactions and every other Go test cited as evidence by formal/claims.json or
    # the docs: a skipped or absent one must fail the real-Postgres gate, not pass silently.
    f"{API_PACKAGE}:TestProjectTransactionsAcrossReplicas",
    f"{API_PACKAGE}:TestProjectTransactionProcessCuts",
    f"{API_PACKAGE}:TestProjectTransactionsProcessRestartBoundaries",
    f"{API_PACKAGE}:TestExportSnapshotNotTornPostgres",
    f"{API_PACKAGE}:TestTemporalProducerToVerifierHistoricalClaim",
    f"{API_PACKAGE}:TestV3AuthorityBindsFinalSemanticRecordAcrossRecorderReseal",
    f"{API_PACKAGE}:TestV3SDKPreparedFixtureSealsWithoutSemanticRewrite",
    f"{STORE_PACKAGE}:TestPostgresProjectWriteTwoPools",
    f"{STORE_PACKAGE}:TestPostgresAppendOnlyRejectsMutation",
    f"{STORE_PACKAGE}:TestPostgresProjectGuardWorksForNonOwnerRuntime",
    f"{RESOURCESHIM_PACKAGE}:TestTokenTheftFailsPoP",
    # Hardening review: pool starvation, pending sweep, runtime privilege and cutover barriers.
    f"{STORE_PACKAGE}:TestPostgresHotProjectDoesNotStarvePool",
    f"{STORE_PACKAGE}:TestPostgresProjectGateCancellation",
    f"{STORE_PACKAGE}:TestPostgresPendingSweepPrunesOnlyUnusableRows",
    f"{PGSCHEMA_PACKAGE}:TestOrdinaryStartupRefusesFreshBootstrap",
    f"{PGSCHEMA_PACKAGE}:TestCutoverRefusesUnnamedMemberWriter",
    f"{API_PACKAGE}:TestUseLedgerOutageIsNotADeny",
    f"{RESOURCESHIM_PACKAGE}:TestLedgerStoreErrorIsNotAReplay",
)


def check_events(lines, required=REQUIRED):
    required = tuple(required)
    if len(set(required)) != len(required) or not required:
        return ["required test list must be nonempty and unique"]
    if any(item.count(":") != 1 or not all(item.split(":", 1)) for item in required):
        return ["required tests must be qualified as package:TestName"]
    seen_run = set()
    seen_pass = set()
    errors = []
    for number, line in enumerate(lines, 1):
        if not line.strip():
            continue
        try:
            event = json.loads(line)
        except json.JSONDecodeError as exc:
            errors.append(f"line {number}: invalid Go test JSON: {exc}")
            continue
        if not isinstance(event, dict):
            errors.append(f"line {number}: Go test event must be a JSON object")
            continue
        package = event.get("Package", "")
        name = event.get("Test", "")
        action = event.get("Action", "")
        if action == "fail":
            errors.append(f"{package or '<unknown package>'} {name or '<package>'}: fail")
        if not isinstance(name, str):
            continue
        for root in required:
            required_package, required_name = root.split(":", 1)
            if package != required_package or (name != required_name and not name.startswith(required_name + "/")):
                continue
            if name == required_name and action == "run":
                seen_run.add(root)
            if name == required_name and action == "pass":
                seen_pass.add(root)
            if action == "skip":
                errors.append(f"{name}: {action}")
            break
    for root in required:
        if root not in seen_run or root not in seen_pass:
            errors.append(f"{root}: missing run/pass event")
    return errors


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--require", action="append", metavar="TEST",
                        help="replace the default required list; repeat for each test")
    args = parser.parse_args()
    errors = check_events(sys.stdin, args.require or REQUIRED)
    if errors:
        for error in errors:
            print(error, file=sys.stderr)
        return 1
    print("required Postgres tests ran and passed without skipped subtests")
    return 0


if __name__ == "__main__":
    sys.exit(main())
