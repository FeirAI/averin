--------------------------- MODULE ConsumeLedger ---------------------------
(***************************************************************************)
(* Consume-before-act (ADR 0003 R5): the resource gateway atomically       *)
(* consumes a capability's use key (INSERT .. ON CONFLICT DO NOTHING in    *)
(* server/internal/pgledger) BEFORE it acts, releases the key only after a  *)
(* failure that provably did not act, and a TTL sweep prunes keys whose     *)
(* consumed_at is older than `Retention`.                                   *)
(*                                                                          *)
(* Several gateway instances race on one ledger. A capability is issued at  *)
(* t = 0 and is valid while clock <= MaxTTL (broker.MaxTTL). It carries     *)
(* UseLimit use keys (single-use: 1; bounded_reuse: N).                    *)
(*                                                                          *)
(* Safety: the resource never acts more than once per use key, i.e. the     *)
(* capability is spent at most UseLimit times -- across instances,          *)
(* releases, and sweeps. The sweep is safe iff Retention >= MaxTTL          *)
(* (main.go enforces a 24h floor against MaxTTL = 1h).                      *)
(***************************************************************************)
EXTENDS Naturals, FiniteSets

CONSTANTS Instances, UseLimit, MaxTTL, Retention, MaxTime

VARIABLES clock, ledger, acted, pc, key

vars == <<clock, ledger, acted, pc, key>>

Keys == 1..UseLimit

TypeOK ==
  /\ clock \in 0..MaxTime
  /\ ledger \subseteq (Keys \X (0..MaxTime))
  /\ acted \in [Keys -> Nat]
  /\ pc \in [Instances -> {"idle", "consumed", "done"}]
  /\ key \in [Instances -> Keys]

Init ==
  /\ clock = 0
  /\ ledger = {}
  /\ acted = [k \in Keys |-> 0]
  /\ pc = [i \in Instances |-> "idle"]
  /\ key \in [Instances -> Keys]

InLedger(k) == \E e \in ledger : e[1] = k

\* A presenter replays the capability at instance i with use key k (the instance checks exp first).
Consume(i, k) ==
  /\ pc[i] \in {"idle", "done"}
  /\ clock <= MaxTTL
  /\ ~InLedger(k)
  /\ ledger' = ledger \cup {<<k, clock>>}
  /\ pc' = [pc EXCEPT ![i] = "consumed"]
  /\ key' = [key EXCEPT ![i] = k]
  /\ UNCHANGED <<clock, acted>>

\* The resource acts; the receipt follows.
Act(i) ==
  /\ pc[i] = "consumed"
  /\ acted' = [acted EXCEPT ![key[i]] = @ + 1]
  /\ pc' = [pc EXCEPT ![i] = "done"]
  /\ UNCHANGED <<clock, ledger, key>>

\* A failure that provably did not act: release the key (retryable).
FailBeforeAct(i) ==
  /\ pc[i] = "consumed"
  /\ ledger' = {e \in ledger : e[1] # key[i]}
  /\ pc' = [pc EXCEPT ![i] = "idle"]
  /\ UNCHANGED <<clock, acted, key>>

\* SweepConsumed: DELETE rows with consumed_at < now - retention.
Sweep ==
  /\ ledger' = {e \in ledger : e[2] + Retention >= clock}
  /\ UNCHANGED <<clock, acted, pc, key>>

Tick ==
  /\ clock < MaxTime
  /\ clock' = clock + 1
  /\ UNCHANGED <<ledger, acted, pc, key>>

Next ==
  \/ \E i \in Instances, k \in Keys : Consume(i, k)
  \/ \E i \in Instances : Act(i) \/ FailBeforeAct(i)
  \/ Sweep
  \/ Tick

Spec == Init /\ [][Next]_vars

(* SAFETY: each use key is acted on at most once, so total spends <= UseLimit. *)
AtMostOncePerKey == \A k \in Keys : acted[k] <= 1

(* While the capability is still live, the ledger never forgets an in-flight key. *)
InFlightRecorded ==
  \A i \in Instances : (pc[i] = "consumed" /\ clock <= MaxTTL) => InLedger(key[i])

(***************************************************************************)
(* Version 0006: old unknown-owner nonces stay global exclusions; new       *)
(* claims are project-scoped. The issue-time bound here is t=0; legacy     *)
(* exclusion removal is safe only after the final old writer was cut off   *)
(* and every old accepted capability is expired. UnsafeMigration switches  *)
(* on premature removal solely to retain its replay counterexample.        *)
(***************************************************************************)
CONSTANTS Projects, P1, P2, LegacyPresent, UnsafeMigration
VARIABLES tenantClock, tenantPhase, tenantCutoverAt, tenantLegacy,
          tenantLedger, tenantPending, tenantActed

tenantVars == <<tenantClock, tenantPhase, tenantCutoverAt, tenantLegacy,
                tenantLedger, tenantPending, tenantActed>>
TenantTypeOK ==
  /\ tenantClock \in 0..MaxTime
  /\ tenantPhase \in {"old", "new"}
  /\ tenantCutoverAt \in 0..MaxTime
  /\ tenantLegacy \in BOOLEAN
  /\ tenantLedger \subseteq Projects
  /\ tenantPending \subseteq Projects
  /\ tenantActed \in [Projects -> Nat]
TenantInit ==
  /\ Init
  /\ tenantClock = 0
  /\ tenantPhase = "old"
  /\ tenantCutoverAt = 0
  /\ tenantLegacy = LegacyPresent
  /\ tenantLedger = {}
  /\ tenantPending = {}
  /\ tenantActed = [p \in Projects |-> IF p = P1 /\ LegacyPresent THEN 1 ELSE 0]
TenantOldAct ==
  /\ tenantPhase = "old"
  /\ ~tenantLegacy
  /\ tenantClock <= MaxTTL
  /\ tenantLegacy' = TRUE
  /\ tenantActed' = [tenantActed EXCEPT ![P1] = @ + 1]
  /\ UNCHANGED <<tenantClock, tenantPhase, tenantCutoverAt, tenantLedger, tenantPending>>
TenantCutover ==
  /\ tenantPhase = "old"
  /\ tenantPhase' = "new"
  /\ tenantCutoverAt' = tenantClock
  /\ UNCHANGED <<tenantClock, tenantLegacy, tenantLedger, tenantPending, tenantActed>>
TenantCanConsume(p) ==
  /\ tenantPhase = "new"
  /\ tenantClock <= MaxTTL
  /\ ~tenantLegacy
  /\ p \notin tenantLedger
TenantConsume(p) ==
  /\ TenantCanConsume(p)
  /\ tenantLedger' = tenantLedger \cup {p}
  /\ tenantPending' = tenantPending \cup {p}
  /\ UNCHANGED <<tenantClock, tenantPhase, tenantCutoverAt, tenantLegacy, tenantActed>>
TenantAct(p) ==
  /\ p \in tenantPending
  /\ tenantPending' = tenantPending \ {p}
  /\ tenantActed' = [tenantActed EXCEPT ![p] = @ + 1]
  /\ UNCHANGED <<tenantClock, tenantPhase, tenantCutoverAt, tenantLegacy, tenantLedger>>
TenantPurge ==
  /\ tenantPhase = "new"
  /\ tenantLegacy
  /\ (UnsafeMigration \/ tenantClock > tenantCutoverAt + MaxTTL)
  /\ tenantLegacy' = FALSE
  /\ UNCHANGED <<tenantClock, tenantPhase, tenantCutoverAt, tenantLedger, tenantPending, tenantActed>>
TenantTick ==
  /\ tenantClock < MaxTime
  /\ tenantClock' = tenantClock + 1
  /\ UNCHANGED <<tenantPhase, tenantCutoverAt, tenantLegacy, tenantLedger, tenantPending, tenantActed>>
TenantNext0 ==
  \/ TenantOldAct
  \/ TenantCutover
  \/ \E p \in Projects : TenantConsume(p) \/ TenantAct(p)
  \/ TenantPurge
  \/ TenantTick
TenantNext == TenantNext0 /\ UNCHANGED vars
TenantSpec == TenantInit /\ [][TenantNext]_<<tenantVars, vars>>
TenantAtMostOnce == \A p \in Projects : tenantActed[p] <= 1
TenantIsolation ==
  (tenantPhase = "new" /\ ~tenantLegacy /\ tenantClock <= MaxTTL /\
   P1 \in tenantLedger /\ P2 \notin tenantLedger) => TenantCanConsume(P2)
=============================================================================
