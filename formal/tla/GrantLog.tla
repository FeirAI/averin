---------------------------- MODULE GrantLog ----------------------------
(***************************************************************************)
(* The grant-transparency log (ADR 0004 D6 / MF2): every credential grant  *)
(* carries a per-project broker_seq bound into its SIGNED evidence, and     *)
(* each checkpoint signs a grant head over the recorded grants. The offline *)
(* verifier requires the anchored set of broker_seqs to be the gapless      *)
(* prefix 1..N and rejects a seq recorded twice; checkpoints are            *)
(* append-only, so ONE anchored gap or duplicate fails the project forever. *)
(*                                                                          *)
(* Modelled on server/internal/api (handleGrant, grant_twophase finalize,   *)
(* native_grant) and store.AllocateBrokerSeq/ReleaseBrokerSeq:             *)
(*   - allocate -> seal -> insert runs under ingestMu (`lock`);             *)
(*   - allocation is MAX(assigned)+1 and idempotent per grant_id;           *)
(*   - a commit can be AMBIGUOUS: it lands, but the server sees an error;   *)
(*   - release deletes the grant's allocation (Postgres DELETE may fail);  *)
(*   - createCheckpoint takes ingestMu and signs the recorded seq set;      *)
(*   - an operator may VOID a reserved, unrecorded seq with a signed        *)
(*     tombstone that fills it (the grant_void remediation).                *)
(*                                                                          *)
(* Switches select the implementation variant under test:                  *)
(*   ReleaseOnError       - every non-ambiguous failure releases the seq    *)
(*   ReleaseCanFail       - the release itself can be lost (PG DELETE err)  *)
(*   FailClosedCheckpoint - createCheckpoint refuses a non-prefix set      *)
(*   ReleaseOnlyIfMax     - release deletes an allocation only while it is  *)
(*                          still the project's max seq                     *)
(*   ReleaseOnlyFresh     - release only a seq THIS attempt allocated, never *)
(*                          one reused from an earlier (maybe ambiguous)    *)
(*                          attempt of the same grant_id                    *)
(*   VoidEnabled          - the operator tombstone remediation exists       *)
(***************************************************************************)
EXTENDS Naturals, FiniteSets

CONSTANTS Grants, ReleaseOnError, ReleaseCanFail, FailClosedCheckpoint, ReleaseOnlyIfMax,
          ReleaseOnlyFresh, VoidEnabled, MaxCheckpoints

VARIABLES seqOf, fresh, rec, voided, pc, anchored, lock, nCheckpoints

vars == <<seqOf, fresh, rec, voided, pc, anchored, lock, nCheckpoints>>

None == 0
Free == "free"
Void == "void"

\* rec: the durable records carrying a broker_seq, as <<seq, writer>> (writer = grant or Void).
Recorded == {r[1] : r \in rec}
Assigned == {seqOf[g] : g \in {h \in Grants : seqOf[h] # None}} \cup voided
MaxSeq == IF Assigned = {} THEN 0 ELSE CHOOSE m \in Assigned : \A n \in Assigned : n <= m
IsPrefix(S) == S = 1..Cardinality(S)
\* Void-then-retry loops allocate ever larger seqs; bound the explored state space (CONSTRAINT).
Bound == 2 * Cardinality(Grants) + 1
StateBound == MaxSeq <= Bound

TypeOK ==
  /\ seqOf \in [Grants -> Nat]
  /\ fresh \in [Grants -> BOOLEAN]
  /\ rec \subseteq Nat \X (Grants \cup {Void})
  /\ voided \subseteq Nat
  /\ pc \in [Grants -> {"idle", "sealing", "failed", "done"}]
  /\ lock \in Grants \cup {Free}

Init ==
  /\ seqOf = [g \in Grants |-> None]
  /\ fresh = [g \in Grants |-> FALSE]
  /\ rec = {}
  /\ voided = {}
  /\ pc = [g \in Grants |-> "idle"]
  /\ anchored = {}
  /\ lock = Free
  /\ nCheckpoints = 0

\* Take ingestMu and allocate (idempotent: a retried grant_id keeps its seq).
Begin(g) ==
  /\ pc[g] = "idle" /\ lock = Free
  /\ lock' = g
  /\ seqOf' = IF seqOf[g] # None THEN seqOf ELSE [seqOf EXCEPT ![g] = MaxSeq + 1]
  /\ fresh' = [fresh EXCEPT ![g] = (seqOf[g] = None)]
  /\ pc' = [pc EXCEPT ![g] = "sealing"]
  /\ UNCHANGED <<rec, voided, anchored, nCheckpoints>>

\* Seal + insert committed and acknowledged.
Commit(g) ==
  /\ pc[g] = "sealing"
  /\ rec' = rec \cup {<<seqOf[g], g>>}
  /\ pc' = [pc EXCEPT ![g] = "done"]
  /\ lock' = Free
  /\ UNCHANGED <<seqOf, fresh, voided, anchored, nCheckpoints>>

\* The commit landed but the server saw an error: the seq stays reserved (never released).
AmbiguousCommit(g) ==
  /\ pc[g] = "sealing"
  /\ rec' = rec \cup {<<seqOf[g], g>>}
  /\ pc' = [pc EXCEPT ![g] = "failed"]
  /\ lock' = Free
  /\ UNCHANGED <<seqOf, fresh, voided, anchored, nCheckpoints>>

\* A deterministic failure after allocation (read error, seal error, insert error): nothing recorded.
Fail(g) ==
  /\ pc[g] = "sealing"
  /\ pc' = [pc EXCEPT ![g] = "failed"]
  /\ lock' = Free
  /\ \/ /\ ReleaseOnError
        /\ ReleaseOnlyIfMax => seqOf[g] = MaxSeq
        /\ ReleaseOnlyFresh => fresh[g]
        /\ seqOf' = [seqOf EXCEPT ![g] = None]
     \/ /\ ReleaseOnError /\ ReleaseOnlyIfMax /\ seqOf[g] # MaxSeq  \* kept: retry fills the hole
        /\ UNCHANGED seqOf
     \/ /\ ReleaseOnError /\ ReleaseOnlyFresh /\ ~fresh[g]  \* reused seq: an earlier attempt may have landed
        /\ UNCHANGED seqOf
     \/ /\ ~ReleaseOnError \/ ReleaseCanFail   \* not released, or the release was lost
        /\ UNCHANGED seqOf
  /\ UNCHANGED <<fresh, rec, voided, anchored, nCheckpoints>>

\* The client may retry a failed grant (same deterministic grant_id) -- or never come back.
Retry(g) ==
  /\ pc[g] = "failed"
  /\ pc' = [pc EXCEPT ![g] = "idle"]
  /\ UNCHANGED <<seqOf, fresh, rec, voided, anchored, lock, nCheckpoints>>

\* Operator remediation: void a reserved seq that no record carries. The tombstone fills the seq,
\* the seq stays in the allocation MAX forever, and the grant_id is detached from it (its retry
\* allocates fresh).
VoidSeq(g) ==
  /\ VoidEnabled
  /\ lock = Free
  /\ pc[g] \in {"failed", "idle"}   \* not mid-seal (the operator takes ingestMu)
  /\ seqOf[g] # None
  /\ seqOf[g] \notin Recorded
  /\ rec' = rec \cup {<<seqOf[g], Void>>}
  /\ voided' = voided \cup {seqOf[g]}
  /\ seqOf' = [seqOf EXCEPT ![g] = None]
  /\ UNCHANGED <<fresh, pc, anchored, lock, nCheckpoints>>

\* createCheckpoint: under ingestMu, sign a grant head over the recorded set.
Checkpoint ==
  /\ lock = Free
  /\ nCheckpoints < MaxCheckpoints
  /\ FailClosedCheckpoint => IsPrefix(Recorded)
  /\ anchored' = anchored \cup {Recorded}
  /\ nCheckpoints' = nCheckpoints + 1
  /\ UNCHANGED <<seqOf, fresh, rec, voided, pc, lock>>

Next ==
  \/ \E g \in Grants : Begin(g) \/ Commit(g) \/ AmbiguousCommit(g) \/ Fail(g) \/ Retry(g) \/ VoidSeq(g)
  \/ Checkpoint

Spec == Init /\ [][Next]_vars

\* Liveness variants. Server progress (a started grant finishes) is always fair. Clients may never
\* retry (no fairness on Retry) unless the config says so; the operator eventually voids (fair VoidSeq).
Progress == \A g \in Grants : WF_vars(Commit(g) \/ AmbiguousCommit(g) \/ Fail(g))
SpecNoRetryNoVoid == Spec /\ Progress
\* Clients always retry, and a grant retried forever eventually commits (strong fairness).
SpecFairRetry == Spec /\ Progress /\ \A g \in Grants :
  WF_vars(Retry(g)) /\ WF_vars(Begin(g)) /\ SF_vars(Commit(g))
\* The operator eventually voids a seq that keeps being voidable (strong fairness): a client
\* retrying a persistently failing grant forever makes the void only intermittently enabled.
SpecFairVoid == Spec /\ Progress /\ \A g \in Grants : SF_vars(VoidSeq(g))

(* SAFETY: every checkpoint ever signed commits a gapless broker_seq prefix. *)
AnchoredGapless == \A S \in anchored : IsPrefix(S)

(* SAFETY: no broker_seq is ever recorded twice (by two grants, or by a grant and a tombstone). *)
NoDuplicateSeq == \A a, b \in rec : a[1] = b[1] => a = b

(* SAFETY (reachability of a clean state): every seq below the max is recorded or still held by a
   grant whose retry will record it. *)
HoleFree == \A n \in 1..MaxSeq : n \in Recorded \/ \E g \in Grants : seqOf[g] = n

(* LIVENESS: a gapped log always becomes checkpointable again (no permanent checkpoint outage). *)
CheckpointRecovers == []<>(IsPrefix(Recorded))
=============================================================================
