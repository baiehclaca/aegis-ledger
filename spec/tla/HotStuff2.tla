------------------------------ MODULE HotStuff2 ------------------------------
\* Safety model of the pipelined HotStuff-2 core in docs/design.md §13.
\*
\* This is an over-approximation, not a liveness proof and not a model of
\* the pacemaker. The adversary may propose two blocks in a view, each
\* extending any already-certified block, including one that is not the
\* highest certificate. Each Byzantine identity adds one vote to every
\* proposal in the view (equivocation), and does not add a second vote to
\* a single proposal. Delivering a quorum certificate to a replica is its
\* own action, so a replica can vote before it has seen that certificate.
\*
\* Direct commit is the design's two-chain rule: a certificate for B
\* whose view is one higher than B's parent commits that parent, and with
\* it every ancestor back to the replica's current commit. A gap commits
\* nothing. A walk that does not meet the current commit commits nothing.

EXTENDS Integers, Sequences, FiniteSets

CONSTANTS N, F, MaxView, MaxId, Byzantine

ASSUME N = 3 * F + 1
ASSUME F \in Nat /\ F >= 1
ASSUME MaxView \in Nat /\ MaxView >= 1
ASSUME MaxId \in Nat /\ MaxId >= 1
ASSUME Byzantine \subseteq (0 .. N - 1)
ASSUME Cardinality(Byzantine) = F

Q == 2 * F + 1
Replicas == 0 .. N - 1
Honest == Replicas \ Byzantine
Views == 1 .. MaxView
Ids == 0 .. MaxId

VARIABLES nblk, parent, viewOf, ancestry, voted, lockB, lockV, comm

vars == <<nblk, parent, viewOf, ancestry, voted, lockB, lockV, comm>>

Init ==
  /\ nblk = 1
  /\ parent = [i \in Ids |-> 0]
  /\ viewOf = [i \in Ids |-> 0]
  /\ ancestry = [i \in Ids |-> IF i = 0 THEN <<0>> ELSE <<>>]
  /\ voted = [r \in Replicas |-> [v \in Views |-> 0]]
  /\ lockB = [r \in Replicas |-> 0]
  /\ lockV = [r \in Replicas |-> 0]
  /\ comm = [r \in Replicas |-> <<0>>]

Exists(b) == b \in 0 .. (nblk - 1)

BlocksIn(v) == {b \in 1 .. (nblk - 1) : viewOf[b] = v}

\* viewOf[b] is only read for a block that has been proposed. Genesis is
\* certified without votes, and an id that has not been issued is not.
VotesFor(b) == {r \in Honest : voted[r][viewOf[b]] = b}

Certified(b) ==
  IF b = 0 THEN TRUE
  ELSE IF ~Exists(b) THEN FALSE
  ELSE Cardinality(VotesFor(b)) + Cardinality(Byzantine) >= Q

Extends(b, lock) == \E i \in 1 .. Len(ancestry[b]) : ancestry[b][i] = lock

Propose(v, p) ==
  /\ v \in Views
  /\ Exists(p)
  /\ Certified(p)
  /\ viewOf[p] < v
  /\ nblk <= MaxId
  /\ Cardinality(BlocksIn(v)) < 2
  /\ parent' = [parent EXCEPT ![nblk] = p]
  /\ viewOf' = [viewOf EXCEPT ![nblk] = v]
  /\ ancestry' = [ancestry EXCEPT ![nblk] = ancestry[p] \o <<nblk>>]
  /\ nblk' = nblk + 1
  /\ UNCHANGED <<voted, lockB, lockV, comm>>

CanVote(r, b) ==
  /\ r \in Honest
  /\ Exists(b) /\ b # 0
  /\ voted[r][viewOf[b]] = 0
  /\ \/ Extends(b, lockB[r])
     \/ viewOf[parent[b]] > lockV[r]

CastVote(r, b) ==
  /\ CanVote(r, b)
  /\ voted' = [voted EXCEPT ![r][viewOf[b]] = b]
  /\ UNCHANGED <<nblk, parent, viewOf, ancestry, lockB, lockV, comm>>

Tip(r) == comm[r][Len(comm[r])]

Connected(seq, tip) == \E i \in 1 .. Len(seq) : seq[i] = tip

IndexOf(seq, tip) == CHOOSE i \in 1 .. Len(seq) : seq[i] = tip

\* The suffix of the parent's chain after this replica's commit tip.
\* Empty when the views are not consecutive or the chains have diverged.
NewCommits(r, b) ==
  LET p == parent[b]
      seq == ancestry[p]
      tip == Tip(r)
  IN IF viewOf[b] = viewOf[p] + 1 /\ Connected(seq, tip)
     THEN SubSeq(seq, IndexOf(seq, tip) + 1, Len(seq))
     ELSE <<>>

Deliver(r, b) ==
  /\ r \in Replicas
  /\ Exists(b) /\ b # 0
  /\ Certified(b)
  /\ LET add == NewCommits(r, b)
         raise == viewOf[b] > lockV[r]
     IN /\ raise \/ add # <<>>
        /\ lockB' = [lockB EXCEPT ![r] = IF raise THEN b ELSE lockB[r]]
        /\ lockV' = [lockV EXCEPT ![r] = IF raise THEN viewOf[b] ELSE lockV[r]]
        /\ comm' = [comm EXCEPT ![r] = comm[r] \o add]
        /\ UNCHANGED <<nblk, parent, viewOf, ancestry, voted>>

Next ==
  \/ \E v \in Views, p \in Ids : Propose(v, p)
  \/ \E r \in Honest, b \in 1 .. MaxId : CastVote(r, b)
  \/ \E r \in Replicas, b \in 1 .. MaxId : Deliver(r, b)

Spec == Init /\ [][Next]_vars

IsPrefix(s, t) ==
  /\ Len(s) <= Len(t)
  /\ \A i \in 1 .. Len(s) : s[i] = t[i]

Agreement ==
  \A r1, r2 \in Replicas :
    \/ IsPrefix(comm[r1], comm[r2])
    \/ IsPrefix(comm[r2], comm[r1])

Chain ==
  \A r \in Replicas :
    /\ comm[r] # <<>>
    /\ comm[r][1] = 0
    /\ \A i \in 1 .. (Len(comm[r]) - 1) : parent[comm[r][i + 1]] = comm[r][i]

Validity ==
  \A r \in Replicas :
    \A i \in 1 .. Len(comm[r]) : Certified(comm[r][i])

OneVote ==
  \A r \in Honest, v \in Views :
    \/ voted[r][v] = 0
    \/ /\ voted[r][v] < nblk
       /\ viewOf[voted[r][v]] = v

StateConstraint == nblk <= MaxId + 1

=============================================================================
