---------------------------- MODULE GrantLog ----------------------------
(***************************************************************************)
(* The grant-transparency log (ADR 0004 D6 / MF2): every credential grant  *)
(* carries a per-project broker_seq bound into its SIGNED evidence, and     *)
(* each checkpoint signs a grant head over the recorded grants. The offline *)
(* verifier requires the anchored set of broker_seqs to be the gapless      *)
(* prefix 1..N; checkpoints are append-only, so ONE anchored gap fails      *)
(* verification of the project forever.                                     *)
(*                                                                          *)
(* Modelled on server/internal/api (handleGrant, grant_twophase finalize,   *)
(* native_grant) and store.AllocateBrokerSeq/ReleaseBrokerSeq:             *)
(*   - allocate -> seal -> insert runs under ingestMu (`lock`);             *)
(*   - allocation is MAX(assigned)+1 and idempotent per grant_id;           *)
(*   - release deletes the grant's allocation (Postgres DELETE may fail);  *)
(*   - createCheckpoint takes ingestMu and signs the recorded seq set.      *)
(*                                                                          *)
(* Switches select the implementation variant under test:                  *)
(*   ReleaseOnError       - every non-ambiguous failure releases the seq    *)
(*   ReleaseCanFail       - the release itself can be lost (PG DELETE err)  *)
(*   FailClosedCheckpoint - createCheckpoint refuses a non-prefix set      *)
(*   ReleaseOnlyIfMax     - release deletes an allocation only while it is  *)
(*                          still the project's max seq; a lower orphan is  *)
(*                          kept so the grant's retry fills the hole        *)
(***************************************************************************)
EXTENDS Naturals, FiniteSets

CONSTANTS Grants, ReleaseOnError, ReleaseCanFail, FailClosedCheckpoint, ReleaseOnlyIfMax,
          MaxCheckpoints

VARIABLES seqOf, recorded, pc, anchored, lock, nCheckpoints

vars == <<seqOf, recorded, pc, anchored, lock, nCheckpoints>>

None == 0
Free == "free"

Assigned == {seqOf[g] : g \in {h \in Grants : seqOf[h] # None}}
MaxSeq == IF Assigned = {} THEN 0 ELSE CHOOSE m \in Assigned : \A n \in Assigned : n <= m
IsPrefix(S) == S = 1..Cardinality(S)

TypeOK ==
  /\ seqOf \in [Grants -> 0..(2 * Cardinality(Grants))]
  /\ recorded \subseteq 1..(2 * Cardinality(Grants))
  /\ pc \in [Grants -> {"idle", "sealing", "failed", "done"}]
  /\ lock \in Grants \cup {Free}

Init ==
  /\ seqOf = [g \in Grants |-> None]
  /\ recorded = {}
  /\ pc = [g \in Grants |-> "idle"]
  /\ anchored = {}
  /\ lock = Free
  /\ nCheckpoints = 0

\* Take ingestMu and allocate (idempotent: a retried grant_id keeps its seq).
Begin(g) ==
  /\ pc[g] = "idle" /\ lock = Free
  /\ lock' = g
  /\ seqOf' = IF seqOf[g] # None THEN seqOf ELSE [seqOf EXCEPT ![g] = MaxSeq + 1]
  /\ pc' = [pc EXCEPT ![g] = "sealing"]
  /\ UNCHANGED <<recorded, anchored, nCheckpoints>>

\* Seal + insert committed.
Commit(g) ==
  /\ pc[g] = "sealing"
  /\ recorded' = recorded \cup {seqOf[g]}
  /\ pc' = [pc EXCEPT ![g] = "done"]
  /\ lock' = Free
  /\ UNCHANGED <<seqOf, anchored, nCheckpoints>>

\* A deterministic failure after allocation (read error, seal error, insert error): nothing recorded.
Fail(g) ==
  /\ pc[g] = "sealing"
  /\ pc' = [pc EXCEPT ![g] = "failed"]
  /\ lock' = Free
  /\ \/ /\ ReleaseOnError
        /\ ReleaseOnlyIfMax => seqOf[g] = MaxSeq
        /\ seqOf' = [seqOf EXCEPT ![g] = None]
     \/ /\ ReleaseOnError /\ ReleaseOnlyIfMax /\ seqOf[g] # MaxSeq  \* kept: retry fills the hole
        /\ UNCHANGED seqOf
     \/ /\ ~ReleaseOnError \/ ReleaseCanFail   \* not released, or the release was lost
        /\ UNCHANGED seqOf
  /\ UNCHANGED <<recorded, anchored, nCheckpoints>>

\* The client may retry a failed grant (same deterministic grant_id) -- or never come back.
Retry(g) ==
  /\ pc[g] = "failed"
  /\ pc' = [pc EXCEPT ![g] = "idle"]
  /\ UNCHANGED <<seqOf, recorded, anchored, lock, nCheckpoints>>

\* createCheckpoint: under ingestMu, sign a grant head over the recorded set.
Checkpoint ==
  /\ lock = Free
  /\ nCheckpoints < MaxCheckpoints
  /\ FailClosedCheckpoint => IsPrefix(recorded)
  /\ anchored' = anchored \cup {recorded}
  /\ nCheckpoints' = nCheckpoints + 1
  /\ UNCHANGED <<seqOf, recorded, pc, lock>>

Next ==
  \/ \E g \in Grants : Begin(g) \/ Commit(g) \/ Fail(g) \/ Retry(g)
  \/ Checkpoint

Spec == Init /\ [][Next]_vars

(* SAFETY: every checkpoint ever signed commits a gapless broker_seq prefix. *)
AnchoredGapless == \A S \in anchored : IsPrefix(S)

(* No permanent hole: every seq below the max is recorded or still held by a grant whose retry
   (same deterministic grant_id) will record it. A violation means no gapless checkpoint can ever
   be signed again: a permanent verification failure, or with FailClosedCheckpoint a permanent
   checkpoint outage. *)
HoleFree == \A n \in 1..MaxSeq : n \in recorded \/ \E g \in Grants : seqOf[g] = n

(* Two recorded grants never share a broker_seq. *)
RecordedSeqsDistinct ==
  \A g, h \in Grants :
    (g # h /\ pc[g] = "done" /\ pc[h] = "done") => seqOf[g] # seqOf[h]
=============================================================================
