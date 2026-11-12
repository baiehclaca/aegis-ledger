------------------------------ MODULE Epoch ------------------------------
\* Epoch membership, kept separate from the HotStuff-2 core.
\*
\* One governance batch per behavior. Seats start as <<1, 2, 3, 4>>.
\* A batch included while the tip is height h takes effect at height
\* h+1+K, which is inclusion height plus the fixed delay. Heights below
\* the effect keep the previous seats. A batch that would leave a length
\* other than 4, or fewer than two live founding organisations, is not
\* applied. Revocation removes the key. Rotation keeps the index and the
\* organisation. An add takes the organisation named in the batch.
\*
\* Keys 1 and 3 are organisation A. Keys 2 and 4 are organisation B.
\* Keys 5 and 6 are organisation A and start unseated.
\*
\* Checked bounds, and only these:
\*   EpochK1.cfg  K=1  MaxH=3
\*   EpochK2.cfg  K=2  MaxH=4
\* The state space is this finite abstraction: n is 4, one batch, and the
\* height stops at MaxH. It is not a model of votes or quorum certificates,
\* and it is not checked at n=7. Those rules stay in the Go tests.
\* HotStuff2.tla remains a fixed validator set. Putting epoch changes into
\* that model would multiply every block by a validator-set history; that
\* product was not model-checked.

EXTENDS Integers, Sequences, FiniteSets

CONSTANTS K, MaxH

ASSUME K \in Nat /\ K >= 1
ASSUME MaxH \in Nat /\ MaxH >= K + 1

Keys == 1 .. 6
Batches == {"lone", "swap", "rot", "add", "mono"}
Seats0 == <<1, 2, 3, 4>>

OrgOf(k) == IF k \in {1, 3, 5, 6} THEN "A" ELSE "B"

Remove(seq, key) == SelectSeq(seq, LAMBDA x : x # key)

LiveOrgs(seq, orgf) == {orgf[seq[i]] : i \in 1 .. Len(seq)}

Legal(seq, orgf) ==
  /\ Len(seq) = 4
  /\ Cardinality(LiveOrgs(seq, orgf)) >= 2

\* Preview is applied to the genesis seats. A behavior includes one batch.
Preview(name) ==
  LET org0 == [k \in Keys |-> OrgOf(k)]
  IN CASE name = "lone" -> [seats |-> Remove(Seats0, 4),
                             org |-> org0,
                             drop |-> {4}]
       [] name = "swap" -> [seats |-> Append(Remove(Seats0, 4), 5),
                             org |-> org0,
                             drop |-> {4}]
       [] name = "rot" -> [seats |-> [i \in 1 .. Len(Seats0) |->
                                       IF Seats0[i] = 4 THEN 5 ELSE Seats0[i]],
                            org |-> [org0 EXCEPT ![5] = org0[4]],
                            drop |-> {4}]
       [] name = "add" -> [seats |-> Append(Seats0, 5),
                            org |-> org0,
                            drop |-> {}]
       [] name = "mono" -> [seats |-> Append(Append(Remove(Remove(Seats0, 2), 4), 5), 6),
                             org |-> org0,
                             drop |-> {2, 4}]

VARIABLES h, seats, revoked, org, batch, effect, applied, hist

vars == <<h, seats, revoked, org, batch, effect, applied, hist>>

Init ==
  /\ h = 0
  /\ seats = Seats0
  /\ revoked = {}
  /\ org = [k \in Keys |-> OrgOf(k)]
  /\ batch = "none"
  /\ effect = 0
  /\ applied = FALSE
  /\ hist = [i \in 0 .. MaxH |-> Seats0]

Include(name) ==
  /\ batch = "none"
  /\ h < MaxH
  /\ batch' = name
  /\ effect' = h + 1 + K
  /\ UNCHANGED <<h, seats, revoked, org, applied, hist>>

Advance ==
  /\ h < MaxH
  /\ h' = h + 1
  /\ batch' = batch
  /\ effect' = effect
  /\ IF batch \in Batches /\ h' = effect /\ ~applied
       THEN LET p == Preview(batch)
            IN IF Legal(p.seats, p.org)
                 THEN /\ seats' = p.seats
                      /\ org' = p.org
                      /\ revoked' = p.drop
                      /\ applied' = TRUE
                      /\ hist' = [hist EXCEPT ![h'] = p.seats]
                 ELSE /\ UNCHANGED <<seats, revoked, org, applied>>
                      /\ hist' = [hist EXCEPT ![h'] = seats]
       ELSE /\ UNCHANGED <<seats, revoked, org, applied>>
            /\ hist' = [hist EXCEPT ![h'] = seats]

Next ==
  \/ \E name \in Batches : Include(name)
  \/ Advance
  \/ (h = MaxH /\ UNCHANGED vars)

Spec == Init /\ [][Next]_vars

\* hist[i] is the seat list after the block at height i.
\* Below the effect height it is the genesis list.
Inv ==
  /\ Len(seats) = 4
  /\ Cardinality(LiveOrgs(seats, org)) >= 2
  /\ \A k \in revoked : \A i \in 1 .. Len(seats) : seats[i] # k
  /\ (batch \in {"lone", "add", "mono"} => ~applied /\ seats = Seats0)
  /\ (applied /\ batch = "swap" =>
        seats = <<1, 2, 3, 5>> /\ org[5] = "A" /\ revoked = {4})
  /\ (applied /\ batch = "rot" =>
        seats = <<1, 2, 3, 5>> /\ org[5] = "B" /\ revoked = {4})
  /\ \A i \in 0 .. h :
        /\ (applied /\ i >= effect => hist[i] = seats)
        /\ (~applied \/ i < effect => hist[i] = Seats0)

=============================================================================
