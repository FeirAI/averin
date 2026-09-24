--------------------------- MODULE GrantRecovery ---------------------------
\* One legacy reservation after transaction-bound issuance is deployed.
\* The project guard excludes every supported grant commit while the fence is
\* inserted. The fence is immutable; a second guarded transaction either
\* recognizes the landed grant or atomically inserts void+marker+terminal.
\* Stuttering represents a crash/restart after any committed transition.
EXTENDS Naturals, FiniteSets

CONSTANT OldWriterAllowed
Ops == {"op1", "op2"}
None == "none"

VARIABLES fence, outcome, records, marker, grantTxn, guard, rejected, crashes, anchored, oldCommitted
vars == <<fence,outcome,records,marker,grantTxn,guard,rejected,crashes,anchored,oldCommitted>>

Init ==
  /\ fence = None /\ outcome = None /\ records = {}
  /\ marker = FALSE /\ grantTxn = "idle" /\ guard = "free"
  /\ rejected = FALSE /\ crashes = 0 /\ anchored = FALSE /\ oldCommitted = FALSE

TypeOK ==
  /\ fence \in Ops \cup {None}
  /\ outcome \in {None,"recorded","voided"}
  /\ records \subseteq {"grant","void"}
  /\ grantTxn \in {"idle","open"}
  /\ guard \in {"free","grant"}
  /\ crashes \in 0..2

GrantBegin ==
  /\ guard = "free" /\ fence = None /\ records = {}
  /\ grantTxn' = "open" /\ guard' = "grant"
  /\ UNCHANGED <<fence,outcome,records,marker,rejected,crashes,anchored,oldCommitted>>

GrantCommit ==
  /\ grantTxn = "open" /\ guard = "grant"
  /\ records' = {"grant"} /\ grantTxn' = "idle" /\ guard' = "free"
  /\ UNCHANGED <<fence,outcome,marker,rejected,crashes,anchored,oldCommitted>>

GrantFail ==
  /\ grantTxn = "open" /\ guard = "grant"
  /\ grantTxn' = "idle" /\ guard' = "free"
  /\ UNCHANGED <<fence,outcome,records,marker,rejected,crashes,anchored,oldCommitted>>

Fence(op) ==
  /\ op \in Ops /\ fence = None /\ guard = "free"
  /\ fence' = op
  /\ UNCHANGED <<outcome,records,marker,grantTxn,guard,rejected,crashes,anchored,oldCommitted>>

CompetingOperation(op) ==
  /\ op \in Ops /\ fence \in Ops /\ fence # op /\ ~rejected
  /\ rejected' = TRUE
  /\ UNCHANGED <<fence,outcome,records,marker,grantTxn,guard,crashes,anchored,oldCommitted>>

Reconcile(op) ==
  /\ op = fence /\ outcome = None /\ guard = "free"
  /\ outcome' = IF "grant" \in records THEN "recorded" ELSE "voided"
  /\ records' = IF "grant" \in records THEN records ELSE {"void"}
  /\ marker' = IF "grant" \in records THEN marker ELSE TRUE
  /\ UNCHANGED <<fence,grantTxn,guard,rejected,crashes,anchored,oldCommitted>>

Crash ==
  /\ crashes < 2 /\ crashes' = crashes + 1
  /\ UNCHANGED <<fence,outcome,records,marker,grantTxn,guard,rejected,anchored,oldCommitted>>

\* An old process with an established credential ignores the new guard/fence.
\* The deployment barrier forbids this action in the safe configuration.
OldWriterCommit ==
  /\ OldWriterAllowed /\ ~oldCommitted
  /\ oldCommitted' = TRUE /\ records' = records \cup {"grant"}
  /\ UNCHANGED <<fence,outcome,marker,grantTxn,guard,rejected,crashes,anchored>>

Checkpoint ==
  /\ ~anchored /\ Cardinality(records) = 1
  /\ ("void" \in records => marker)
  /\ anchored' = TRUE
  /\ UNCHANGED <<fence,outcome,records,marker,grantTxn,guard,rejected,crashes,oldCommitted>>

Idle == outcome # None /\ UNCHANGED vars

Next ==
  \/ GrantBegin \/ GrantCommit \/ GrantFail
  \/ \E op \in Ops : Fence(op) \/ CompetingOperation(op) \/ Reconcile(op)
  \/ Crash \/ OldWriterCommit \/ Checkpoint \/ Idle

Spec == Init /\ [][Next]_vars
\* Fair DB resolution and an eventually scheduled authorized operator. Grant
\* failures may recur forever; strong fairness of the fence lets recovery win
\* one of the openings. Permanent DB failure is outside this liveness claim.
FairRecovery == Spec /\ WF_vars(GrantCommit \/ GrantFail)
  /\ SF_vars(\E op \in Ops : Fence(op))
  /\ \A op \in Ops : WF_vars(Reconcile(op))

NoDuplicateSeq == Cardinality(records) <= 1
AnchoredGapless == anchored => Cardinality(records) = 1
NoLateGrant == outcome = "voided" => "grant" \notin records
TerminalHasWinner == outcome # None => Cardinality(records) = 1
TerminalOnceFenced == outcome # None => fence # None
CheckpointRecovers == <> (outcome # None)
=============================================================================
