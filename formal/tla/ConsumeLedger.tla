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
=============================================================================
