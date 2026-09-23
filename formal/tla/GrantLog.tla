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
(*   - a commit can be AMBIGUOUS: the server sees an error and frees        *)
(*     ingestMu, while the transaction is still in flight at the database;  *)
(*     it later LANDS or ABORTS (a separate step, so a void can interleave);*)
(*   - release deletes the grant's allocation (Postgres DELETE may fail);  *)
(*   - createCheckpoint takes ingestMu and signs the recorded seq set;      *)
(*   - an operator may VOID a reserved, unrecorded seq with a signed        *)
(*     tombstone that fills it (the grant_void remediation). The tombstone  *)
(*     reuses the grant's record_id, and the voided grant_id is RETIRED:    *)
(*     a later allocation for it is refused (409), never re-issued.         *)
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
(*   UniqueIndex          - records has UNIQUE(project, record_id): the     *)
(*                          tombstone and the grant's insert share a        *)
(*                          record_id, so at most one lands; the void does  *)
(*                          NOT wait for in-flight inserts, a late insert   *)
(*                          after the tombstone aborts (0002 fallback: FALSE)*)
(*   AgeFromLastAttempt   - the void's minimum age is measured from the     *)
(*                          grant's LAST attempt (so no attempt of it can   *)
(*                          still be in flight); FALSE = from the original  *)
(*                          allocation, which only protects the FIRST one   *)
(*                                                                          *)
(* No CONSTRAINT: allocation beyond Bound is disabled in Begin itself, and  *)
(* the passing configs assert BoundNotBinding, i.e. the bound never cuts a  *)
(* behaviour (TLC's liveness checking is unsound under a CONSTRAINT).       *)
(***************************************************************************)
EXTENDS Naturals, FiniteSets

CONSTANTS Grants, ReleaseOnError, ReleaseCanFail, FailClosedCheckpoint, ReleaseOnlyIfMax,
          ReleaseOnlyFresh, VoidEnabled, UniqueIndex, AgeFromLastAttempt, MaxCheckpoints

VARIABLES seqOf, fresh, rec, voided, retired, inflight, pc, anchored, lock, nCheckpoints

vars == <<seqOf, fresh, rec, voided, retired, inflight, pc, anchored, lock, nCheckpoints>>

None == 0
Free == "free"
Void == "void"

\* rec: the durable records carrying a broker_seq, as <<seq, writer>> (writer = grant or Void).
\* inflight: ambiguous commits still open at the database, as <<seq, grant, attempt-was-fresh>>.
Recorded == {r[1] : r \in rec}
Assigned == {seqOf[g] : g \in {h \in Grants : seqOf[h] # None}} \cup voided
MaxSeq == IF Assigned = {} THEN 0 ELSE CHOOSE m \in Assigned : \A n \in Assigned : n <= m
IsPrefix(S) == S = 1..Cardinality(S)
InFlight(g) == \E e \in inflight : e[2] = g
\* Explored allocation bound (enforced in Begin, never a CONSTRAINT).
Bound == 2 * Cardinality(Grants) + 1

TypeOK ==
  /\ seqOf \in [Grants -> Nat]
  /\ fresh \in [Grants -> BOOLEAN]
  /\ rec \subseteq Nat \X (Grants \cup {Void})
  /\ voided \subseteq Nat
  /\ retired \subseteq Grants
  /\ inflight \subseteq Nat \X Grants \X BOOLEAN
  /\ pc \in [Grants -> {"idle", "sealing", "failed", "done"}]
  /\ lock \in Grants \cup {Free}

Init ==
  /\ seqOf = [g \in Grants |-> None]
  /\ fresh = [g \in Grants |-> FALSE]
  /\ rec = {}
  /\ voided = {}
  /\ retired = {}
  /\ inflight = {}
  /\ pc = [g \in Grants |-> "idle"]
  /\ anchored = {}
  /\ lock = Free
  /\ nCheckpoints = 0

\* Take ingestMu and allocate (idempotent: a retried grant_id keeps its seq; a retired one is refused).
Begin(g) ==
  /\ pc[g] = "idle" /\ lock = Free
  /\ g \notin retired
  /\ seqOf[g] = None => MaxSeq < Bound
  /\ lock' = g
  /\ seqOf' = IF seqOf[g] # None THEN seqOf ELSE [seqOf EXCEPT ![g] = MaxSeq + 1]
  /\ fresh' = [fresh EXCEPT ![g] = (seqOf[g] = None)]
  /\ pc' = [pc EXCEPT ![g] = "sealing"]
  /\ UNCHANGED <<rec, voided, retired, inflight, anchored, nCheckpoints>>

\* Seal + insert committed and acknowledged.
Commit(g) ==
  /\ pc[g] = "sealing"
  /\ rec' = rec \cup {<<seqOf[g], g>>}
  /\ pc' = [pc EXCEPT ![g] = "done"]
  /\ lock' = Free
  /\ UNCHANGED <<seqOf, fresh, voided, retired, inflight, anchored, nCheckpoints>>

\* The server sees an error, but the transaction is still open at the database: the seq stays
\* reserved (never released), and the insert may still land after ingestMu is freed.
AmbiguousSend(g) ==
  /\ pc[g] = "sealing"
  /\ inflight' = inflight \cup {<<seqOf[g], g, fresh[g]>>}
  /\ pc' = [pc EXCEPT ![g] = "failed"]
  /\ lock' = Free
  /\ UNCHANGED <<seqOf, fresh, rec, voided, retired, anchored, nCheckpoints>>

\* The in-flight insert lands. Under the UNIQUE index it cannot land once a tombstone holds its
\* record_id (the grant_id, now retired).
Land(e) ==
  /\ e \in inflight
  /\ UniqueIndex => e[2] \notin retired
  /\ rec' = rec \cup {<<e[1], e[2]>>}
  /\ inflight' = inflight \ {e}
  /\ UNCHANGED <<seqOf, fresh, voided, retired, pc, anchored, lock, nCheckpoints>>

\* ...or it aborts (timeout, unique violation): nothing recorded.
Abort(e) ==
  /\ e \in inflight
  /\ inflight' = inflight \ {e}
  /\ UNCHANGED <<seqOf, fresh, rec, voided, retired, pc, anchored, lock, nCheckpoints>>

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
  /\ UNCHANGED <<fresh, rec, voided, retired, inflight, anchored, nCheckpoints>>

\* The client may retry a failed grant (same deterministic grant_id) -- or never come back.
Retry(g) ==
  /\ pc[g] = "failed"
  /\ pc' = [pc EXCEPT ![g] = "idle"]
  /\ UNCHANGED <<seqOf, fresh, rec, voided, retired, inflight, anchored, lock, nCheckpoints>>

\* Operator remediation: void a reserved seq that no COMMITTED record carries (the store read cannot
\* see an in-flight insert). The tombstone fills the seq, the seq stays in the allocation MAX
\* forever, and the grant_id is retired.
\*   - AgeFromLastAttempt: the minimum age exceeds any commit's lifetime, measured from the grant's
\*     last attempt, so no attempt of it is still in flight. Measured from the allocation instead,
\*     it only guarantees that the FIRST (fresh) attempt is resolved; a later retry may be open.
\*   - UniqueIndex adds no guard here: it acts in Land, where an in-flight insert of a retired
\*     grant can no longer land (the tombstone holds its record_id), so it can only abort. The two
\*     guards are independent mechanisms, and the index configs exercise that backstop.
VoidSeq(g) ==
  /\ VoidEnabled
  /\ lock = Free
  /\ pc[g] \in {"failed", "idle"}   \* not mid-seal (the operator takes ingestMu)
  /\ g \notin retired
  /\ seqOf[g] # None
  /\ seqOf[g] \notin Recorded
  /\ AgeFromLastAttempt => ~InFlight(g)
  /\ ~\E e \in inflight : e[2] = g /\ e[3]
  /\ rec' = rec \cup {<<seqOf[g], Void>>}
  /\ voided' = voided \cup {seqOf[g]}
  /\ retired' = retired \cup {g}
  /\ seqOf' = [seqOf EXCEPT ![g] = None]
  /\ UNCHANGED <<fresh, inflight, pc, anchored, lock, nCheckpoints>>

\* createCheckpoint: under ingestMu, sign a grant head over the recorded set.
Checkpoint ==
  /\ lock = Free
  /\ nCheckpoints < MaxCheckpoints
  /\ FailClosedCheckpoint => IsPrefix(Recorded)
  /\ anchored' = anchored \cup {Recorded}
  /\ nCheckpoints' = nCheckpoints + 1
  /\ UNCHANGED <<seqOf, fresh, rec, voided, retired, inflight, pc, lock>>

Next ==
  \/ \E g \in Grants : Begin(g) \/ Commit(g) \/ AmbiguousSend(g) \/ Fail(g) \/ Retry(g) \/ VoidSeq(g)
  \/ \E e \in inflight : Land(e) \/ Abort(e)
  \/ Checkpoint

Spec == Init /\ [][Next]_vars

\* Liveness variants. Server progress (a started grant finishes, an open transaction resolves) is
\* always fair. Clients may never retry (no fairness on Retry) unless the config says so; the
\* operator eventually voids (fair VoidSeq).
Resolve(g) == \E e \in inflight : e[2] = g /\ (Land(e) \/ Abort(e))
Progress == \A g \in Grants :
  WF_vars(Commit(g) \/ AmbiguousSend(g) \/ Fail(g)) /\ WF_vars(Resolve(g))
SpecNoRetryNoVoid == Spec /\ Progress
\* Clients always retry, and a grant retried forever eventually commits (strong fairness).
SpecFairRetry == Spec /\ Progress /\ \A g \in Grants :
  WF_vars(Retry(g)) /\ WF_vars(Begin(g)) /\ SF_vars(Commit(g))
\* The operator eventually voids a seq that keeps being voidable (strong fairness). Because the
\* void's age runs from the grant's LAST attempt, a client that retries forever with every attempt
\* failing starves the void (TLC finds this without the SF on Commit); so recovery additionally
\* assumes a grant that is retried forever eventually commits. A client that gives up is covered by
\* the void alone.
SpecVoidOnly == Spec /\ Progress /\ \A g \in Grants : SF_vars(VoidSeq(g))
SpecFairVoid == SpecVoidOnly /\ \A g \in Grants : SF_vars(Commit(g))

(* SAFETY: every checkpoint ever signed commits a gapless broker_seq prefix. *)
AnchoredGapless == \A S \in anchored : IsPrefix(S)

(* SAFETY: no broker_seq is ever recorded twice (by two grants, or by a grant and a tombstone). *)
NoDuplicateSeq == \A a, b \in rec : a[1] = b[1] => a = b

(* SAFETY (reachability of a clean state): every seq below the max is recorded or still held by a
   grant whose retry will record it. *)
HoleFree == \A n \in 1..MaxSeq : n \in Recorded \/ \E g \in Grants : seqOf[g] = n

(* NON-VACUITY: expected VIOLATED in the shipped design. The guards still let the operator void a
   grant whose ambiguous commit has resolved, so the passing safety configs exercise the void. *)
NoVoid == retired = {}

(* BACKSTOP REACHABILITY: expected VIOLATED under the index alone, i.e. a grant is voided while an
   attempt of it is still in flight, and only the UNIQUE index stops that attempt landing. *)
NoVoidDuringFlight == \A g \in retired : ~InFlight(g)

(* The Begin guard never disables an allocation, so bounding the model cuts no behaviour. *)
BoundNotBinding == MaxSeq < Bound

(* LIVENESS: a gapped log always becomes checkpointable again (no permanent checkpoint outage). *)
CheckpointRecovers == []<>(IsPrefix(Recorded))
=============================================================================
