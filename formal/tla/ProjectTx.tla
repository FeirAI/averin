----------------------------- MODULE ProjectTx ----------------------------
(***************************************************************************)
(* Two replicas have disjoint local caches and locks. A project guard is a *)
(* persisted DB row held from authoritative read through commit. Commit may*)
(* be acknowledged ambiguously; reconciliation checks the same identity.  *)
(* Restart loses caches, while records, pending and revocation persist.     *)
(* Checkpoint anchors attach only after the checkpoint commits.            *)
(***************************************************************************)
EXTENDS Naturals, FiniteSets, Sequences
CONSTANTS Replicas, Serialize, Authoritative
VARIABLES records, phase, snap, checkpoints, cpPhase, cpSnap, cpSeq,
          guard, revoked, cacheRevoked, useDone, badUse, pending,
          cachePending, prepared, finalized, badFinalize, alive, crashed, anchors
vars == <<records, phase, snap, checkpoints, cpPhase, cpSnap, cpSeq,
          guard, revoked, cacheRevoked, useDone, badUse, pending,
          cachePending, prepared, finalized, badFinalize, alive, crashed, anchors>>
Free == 0
CanEnter == ~Serialize \/ guard = Free
Entries == {checkpoints[j] : j \in 1..Len(checkpoints)}
Init ==
  /\ records = {} /\ phase = [i \in Replicas |-> "idle"]
  /\ snap = [i \in Replicas |-> {}]
  /\ checkpoints = <<>> /\ cpPhase = [i \in Replicas |-> "idle"]
  /\ cpSnap = [i \in Replicas |-> {}] /\ cpSeq = [i \in Replicas |-> 0]
  /\ guard = Free /\ revoked = FALSE
  /\ cacheRevoked = [i \in Replicas |-> FALSE]
  /\ useDone = [i \in Replicas |-> FALSE] /\ badUse = FALSE
  /\ pending = FALSE /\ cachePending = [i \in Replicas |-> FALSE]
  /\ prepared = FALSE /\ finalized = FALSE /\ badFinalize = FALSE
  /\ alive = [i \in Replicas |-> TRUE]
  /\ crashed = [i \in Replicas |-> FALSE] /\ anchors = {}
BeginRec(i) ==
  /\ alive[i] /\ phase[i] = "idle" /\ CanEnter
  /\ phase' = [phase EXCEPT ![i] = "open"]
  /\ snap' = [snap EXCEPT ![i] = records]
  /\ guard' = IF Serialize THEN i ELSE guard
  /\ UNCHANGED <<records, checkpoints, cpPhase, cpSnap, cpSeq, revoked,
                 cacheRevoked, useDone, badUse, pending, cachePending,
                 prepared, finalized, badFinalize, alive, crashed, anchors>>
FinishRec(i, result) ==
  /\ alive[i] /\ phase[i] = "open"
  /\ result \in {"commit", "ambiguous-land", "ambiguous-abort"}
  /\ records' = IF result = "ambiguous-abort" THEN records ELSE records \cup {i}
  /\ phase' = [phase EXCEPT ![i] = IF result = "commit" THEN "done" ELSE "uncertain"]
  /\ guard' = IF Serialize THEN Free ELSE guard
  /\ UNCHANGED <<snap, checkpoints, cpPhase, cpSnap, cpSeq, revoked,
                 cacheRevoked, useDone, badUse, pending, cachePending,
                 prepared, finalized, badFinalize, alive, crashed, anchors>>
Reconcile(i) ==
  /\ alive[i] /\ phase[i] = "uncertain"
  /\ phase' = [phase EXCEPT ![i] = IF i \in records THEN "done" ELSE "aborted"]
  /\ UNCHANGED <<records, snap, checkpoints, cpPhase, cpSnap, cpSeq, guard,
                 revoked, cacheRevoked, useDone, badUse, pending,
                 cachePending, prepared, finalized, badFinalize, alive,
                 crashed, anchors>>
BeginCP(i) ==
  /\ alive[i] /\ cpPhase[i] = "idle" /\ CanEnter
  /\ cpPhase' = [cpPhase EXCEPT ![i] = "open"]
  /\ cpSnap' = [cpSnap EXCEPT ![i] = records]
  /\ cpSeq' = [cpSeq EXCEPT ![i] = Len(checkpoints)+1]
  /\ guard' = IF Serialize THEN i ELSE guard
  /\ UNCHANGED <<records, phase, snap, checkpoints, revoked, cacheRevoked,
                 useDone, badUse, pending, cachePending, prepared, finalized,
                 badFinalize, alive, crashed, anchors>>
CommitCP(i) ==
  /\ alive[i] /\ cpPhase[i] = "open"
  /\ checkpoints' = Append(checkpoints,
       [seq |-> cpSeq[i], frontier |-> cpSnap[i], atCommit |-> records])
  /\ cpPhase' = [cpPhase EXCEPT ![i] = "done"]
  /\ guard' = IF Serialize THEN Free ELSE guard
  /\ UNCHANGED <<records, phase, snap, cpSnap, cpSeq, revoked, cacheRevoked,
                 useDone, badUse, pending, cachePending, prepared, finalized,
                 badFinalize, alive, crashed, anchors>>
AttachAnchor(j) ==
  /\ j \in 1..Len(checkpoints) /\ j \notin anchors
  /\ anchors' = anchors \cup {j}
  /\ UNCHANGED <<records, phase, snap, checkpoints, cpPhase, cpSnap, cpSeq,
                 guard, revoked, cacheRevoked, useDone, badUse, pending,
                 cachePending, prepared, finalized, badFinalize, alive, crashed>>
Revoke(i) ==
  /\ alive[i] /\ ~revoked /\ CanEnter
  /\ revoked' = TRUE
  /\ cacheRevoked' = [cacheRevoked EXCEPT ![i] = TRUE]
  /\ UNCHANGED <<records, phase, snap, checkpoints, cpPhase, cpSnap, cpSeq,
                 guard, useDone, badUse, pending, cachePending, prepared,
                 finalized, badFinalize, alive, crashed, anchors>>
Use(i) ==
  /\ alive[i] /\ ~useDone[i] /\ CanEnter
  /\ useDone' = [useDone EXCEPT ![i] = TRUE]
  /\ badUse' = (badUse \/ (revoked /\ ~(IF Authoritative THEN revoked ELSE cacheRevoked[i])))
  /\ UNCHANGED <<records, phase, snap, checkpoints, cpPhase, cpSnap, cpSeq,
                 guard, revoked, cacheRevoked, pending, cachePending,
                 prepared, finalized, badFinalize, alive, crashed, anchors>>
Prepare(i) ==
  /\ alive[i] /\ ~prepared /\ CanEnter
  /\ prepared' = TRUE /\ pending' = TRUE
  /\ cachePending' = [cachePending EXCEPT ![i] = TRUE]
  /\ UNCHANGED <<records, phase, snap, checkpoints, cpPhase, cpSnap, cpSeq,
                 guard, revoked, cacheRevoked, useDone, badUse, finalized,
                 badFinalize, alive, crashed, anchors>>
Expire ==
  /\ pending
  /\ pending' = FALSE
  /\ UNCHANGED <<records, phase, snap, checkpoints, cpPhase, cpSnap, cpSeq,
                 guard, revoked, cacheRevoked, useDone, badUse, cachePending,
                 prepared, finalized, badFinalize, alive, crashed, anchors>>
Finalize(i) ==
  /\ alive[i] /\ ~finalized /\ CanEnter
  /\ (IF Authoritative THEN pending ELSE cachePending[i])
  /\ finalized' = TRUE /\ pending' = FALSE
  /\ badFinalize' = (badFinalize \/ ~pending)
  /\ UNCHANGED <<records, phase, snap, checkpoints, cpPhase, cpSnap, cpSeq,
                 guard, revoked, cacheRevoked, useDone, badUse, cachePending,
                 prepared, alive, crashed, anchors>>
Refresh(i) ==
  /\ alive[i] /\ (cacheRevoked[i] # revoked \/ cachePending[i] # pending)
  /\ cacheRevoked' = [cacheRevoked EXCEPT ![i] = revoked]
  /\ cachePending' = [cachePending EXCEPT ![i] = pending]
  /\ UNCHANGED <<records, phase, snap, checkpoints, cpPhase, cpSnap, cpSeq,
                 guard, revoked, useDone, badUse, pending, prepared,
                 finalized, badFinalize, alive, crashed, anchors>>
Crash(i) ==
  /\ alive[i] /\ ~crashed[i]
  /\ alive' = [alive EXCEPT ![i] = FALSE]
  /\ crashed' = [crashed EXCEPT ![i] = TRUE]
  /\ phase' = IF phase[i] = "open" THEN [phase EXCEPT ![i] = "aborted"] ELSE phase
  /\ cpPhase' = IF cpPhase[i] = "open" THEN [cpPhase EXCEPT ![i] = "aborted"] ELSE cpPhase
  /\ guard' = IF Serialize /\ guard = i THEN Free ELSE guard
  /\ UNCHANGED <<records, snap, checkpoints, cpSnap, cpSeq, revoked,
                 cacheRevoked, useDone, badUse, pending, cachePending,
                 prepared, finalized, badFinalize, anchors>>
Restart(i) ==
  /\ ~alive[i] /\ crashed[i]
  /\ alive' = [alive EXCEPT ![i] = TRUE]
  /\ cacheRevoked' = [cacheRevoked EXCEPT ![i] = FALSE]
  /\ cachePending' = [cachePending EXCEPT ![i] = FALSE]
  /\ UNCHANGED <<records, phase, snap, checkpoints, cpPhase, cpSnap, cpSeq,
                 guard, revoked, useDone, badUse, pending, prepared,
                 finalized, badFinalize, crashed, anchors>>
Next ==
  \/ \E i \in Replicas : BeginRec(i) \/ Reconcile(i) \/ BeginCP(i) \/ CommitCP(i)
                         \/ Revoke(i) \/ Use(i) \/ Prepare(i) \/ Finalize(i)
                         \/ Refresh(i) \/ Crash(i) \/ Restart(i)
                         \/ \E result \in {"commit", "ambiguous-land", "ambiguous-abort"} : FinishRec(i,result)
  \/ Expire
  \/ \E j \in 1..Len(checkpoints) : AttachAnchor(j)
Spec == Init /\ [][Next]_vars
CoreNext ==
  \/ \E i \in Replicas : BeginRec(i) \/ Reconcile(i) \/ BeginCP(i) \/ CommitCP(i)
                         \/ Crash(i) \/ Restart(i)
                         \/ \E result \in {"commit", "ambiguous-land", "ambiguous-abort"} : FinishRec(i,result)
  \/ \E j \in 1..Len(checkpoints) : AttachAnchor(j)
OperationalNext ==
  \/ \E i \in Replicas : Revoke(i) \/ Use(i) \/ Prepare(i) \/ Finalize(i)
                         \/ Refresh(i) \/ Crash(i) \/ Restart(i)
  \/ Expire
CoreSpec == Init /\ [][CoreNext]_vars
OperationalSpec == Init /\ [][OperationalNext]_vars
NoFrontierFork == records # Replicas \/ \E i \in Replicas : snap[i] = Replicas \ {i}
NoCheckpointFork == \A a,b \in 1..Len(checkpoints) : a # b => checkpoints[a].seq # checkpoints[b].seq
NoStaleCheckpoint == \A e \in Entries : e.frontier = e.atCommit
NoRevokedUse == ~badUse
NoGhostFinalize == ~badFinalize
=============================================================================
