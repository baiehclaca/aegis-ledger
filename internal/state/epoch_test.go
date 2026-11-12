package state

import (
	"bytes"
	"errors"
	"slices"
	"testing"

	"github.com/silvergreyhound/silver-grey-ledger/internal/crypto"
	"github.com/silvergreyhound/silver-grey-ledger/internal/types"
)

func TestEpochSwitchRotationAndRevocation(t *testing.T) {
	keys := mlKeys(t, 4)
	g := genesisWith(t, 2, 2, keys, nil)
	led := mustLedger(t, g)
	chain := led.Chain()
	old := keys[3]
	oldPub := mustPub(t, old)
	oldID := mustID(t, oldPub)
	neu := mlKeys(t, 1)[0]
	newPub := mustPub(t, neu)

	rotate := types.GovAction{Kind: types.GovRotate, KeyID: oldID}
	if err := rotate.SignRotate(chain, oldID, old, neu); err != nil {
		t.Fatal(err)
	}
	tx := types.GovTx{ChainID: chain, Actions: []types.GovAction{rotate}}
	signAdmins(t, &tx, keys)
	next, err := led.Transition(1, nil, []types.GovTx{tx})
	if err != nil {
		t.Fatal(err)
	}
	if _, live := seatKey(t, next, 3); live != oldID {
		t.Fatal("rotation applied before the epoch")
	}
	mid, err := next.Transition(2, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, live := seatKey(t, mid, 3); live != oldID {
		t.Fatal("rotation applied one block early")
	}
	done, err := mid.Transition(3, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, live := seatKey(t, done, 3); live != mustID(t, newPub) {
		t.Fatal("rotated key is not seated at the epoch")
	}
	live, err := done.SignerLive(4, 3)
	if err != nil || !live {
		t.Fatalf("new key live: %v %v", live, err)
	}
	_, _, revoked, ok := done.Identity(oldPub, 3)
	if !ok || !revoked {
		t.Fatal("old key was not revoked at the epoch")
	}
	if seated, err := done.SignerLive(3, 3); err != nil || !seated {
		t.Fatal("rotated seat was not live at the epoch height")
	}
	ev := eventFrom(t, chain, neu, 1, types.ReadAllMembers)
	if _, err := done.Transition(4, []types.Event{ev}, nil); err != nil {
		t.Fatal(err)
	}
	stale := eventFrom(t, chain, old, 1, types.ReadAllMembers)
	if _, err := done.Transition(4, []types.Event{stale}, nil); !errors.Is(err, ErrTransition) {
		t.Fatalf("revoked writer accepted: %v", err)
	}

	// Revocation removes the seat. An add in the same batch keeps n = 4.
	// The revoked key's later events are rejected and earlier ones can be suspect.
	revokedKey := keys[1]
	revokedID := mustID(t, mustPub(t, revokedKey))
	spare := mlKeys(t, 1)[0]
	rev := types.GovAction{Kind: types.GovRevokeKey, KeyID: revokedID, SuspectSince: 1}
	add := types.GovAction{Kind: types.GovAddValidator, Key: mustPub(t, spare), Org: "founding-0", Address: "local"}
	rtx := types.GovTx{ChainID: chain, Actions: []types.GovAction{rev, add}}
	signAdmins(t, &rtx, keys)
	base := mustLedger(t, g)
	inc, err := base.Transition(1, []types.Event{eventFrom(t, chain, revokedKey, 1, types.ReadAllMembers)}, []types.GovTx{rtx})
	if err != nil {
		t.Fatal(err)
	}
	after, err := inc.Transition(2, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := after.ValidatorKeys(); err != nil || len(got) != 4 || !got[1].Equal(mustPub(t, revokedKey)) {
		t.Fatal("revocation applied before the epoch")
	}
	effect, err := after.Transition(3, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !effect.Suspect(revokedID, 2) {
		t.Fatal("event after suspect_since was not marked")
	}
	if effect.Suspect(revokedID, 1) {
		t.Fatal("event at the flagged height was marked suspect")
	}
	if _, err := effect.Transition(4, []types.Event{eventFrom(t, chain, revokedKey, 2, types.ReadAllMembers)}, nil); !errors.Is(err, ErrTransition) {
		t.Fatal("revoked key signed an accepted event")
	}
	voters, err := effect.ValidatorKeys()
	if err != nil || len(voters) != 4 {
		t.Fatalf("epoch size %v %d", err, len(voters))
	}
	for _, key := range voters {
		id, err := key.ID()
		if err != nil {
			t.Fatal(err)
		}
		if id == revokedID {
			t.Fatal("revoked key stayed in the validator set")
		}
	}
}

func TestGovernanceThreshold(t *testing.T) {
	founders := slhKeys(t, 3)
	keys := mlKeys(t, 4)
	g := genesisWith(t, 3, 2, keys, founders)
	led := mustLedger(t, g)
	chain := led.Chain()
	tx := types.GovTx{ChainID: chain, Actions: []types.GovAction{{
		Kind: types.GovExtendRegistry, EventType: 9, Name: "extra",
	}}}
	if _, err := led.Transition(1, nil, []types.GovTx{tx}); !errors.Is(err, ErrTransition) {
		t.Fatal("zero signatures were accepted")
	}
	if err := tx.SignAdmin(keys[0]); err != nil {
		t.Fatal(err)
	}
	if _, err := led.Transition(1, nil, []types.GovTx{tx}); !errors.Is(err, ErrTransition) {
		t.Fatal("one organisation met a threshold of two")
	}
	same := tx
	if err := same.SignAdmin(keys[3]); err != nil {
		t.Fatal(err)
	}
	if _, err := led.Transition(1, nil, []types.GovTx{same}); !errors.Is(err, ErrTransition) {
		t.Fatal("two signatures from one organisation were accepted")
	}
	ok := tx
	if err := ok.SignAdmin(keys[1]); err != nil {
		t.Fatal(err)
	}
	if _, err := led.Transition(1, nil, []types.GovTx{ok}); err != nil {
		t.Fatal(err)
	}
}

func TestEpochSizeAndReadPolicy(t *testing.T) {
	keys := mlKeys(t, 4)
	g := genesisWith(t, 2, 1, keys, nil)
	led := mustLedger(t, g)
	chain := led.Chain()
	extra := mlKeys(t, 1)[0]
	add := types.GovTx{ChainID: chain, Actions: []types.GovAction{{
		Kind: types.GovAddValidator, Key: mustPub(t, extra), Org: "founding-0", Address: "local",
	}}}
	signAdmins(t, &add, keys)
	if _, err := led.Transition(1, nil, []types.GovTx{add}); !errors.Is(err, ErrTransition) {
		t.Fatal("a validator set of 5 was accepted")
	}
	drop := types.GovTx{ChainID: chain, Actions: []types.GovAction{{
		Kind: types.GovRemoveValidator, KeyID: mustID(t, mustPub(t, keys[3])),
	}}}
	signAdmins(t, &drop, keys)
	if _, err := led.Transition(1, nil, []types.GovTx{drop}); !errors.Is(err, ErrTransition) {
		t.Fatal("a validator set of 3 was accepted")
	}

	readerA := mlKeys(t, 1)[0]
	readerB := mlKeys(t, 1)[0]
	auditor := mlKeys(t, 1)[0]
	led = ledgerWithReaders(t, keys, readerA, readerB, auditor)
	chain = led.Chain()
	ev := eventFrom(t, chain, keys[0], 1, types.ReadOrgOnly)
	next, err := led.Transition(1, []types.Event{ev}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !next.CanRead(mustPub(t, readerA), ev, 1) {
		t.Fatal("same organisation could not read")
	}
	if next.CanRead(mustPub(t, readerB), ev, 1) {
		t.Fatal("other organisation could read an org-only event")
	}
	if !next.CanRead(mustPub(t, auditor), ev, 1) {
		t.Fatal("auditor could not read")
	}
	hidden := eventFrom(t, chain, keys[0], 2, types.ReadAuditors)
	if _, err := next.Transition(2, []types.Event{hidden}, nil); err != nil {
		t.Fatal(err)
	}
	if next.CanRead(mustPub(t, readerA), hidden, 2) {
		t.Fatal("a reader saw an auditors-only event")
	}
	outsider := mlKeys(t, 1)[0]
	if next.CanRead(mustPub(t, outsider), ev, 1) {
		t.Fatal("a non-member could read")
	}
}

func TestPendingRootsDiffer(t *testing.T) {
	keys := mlKeys(t, 4)
	g := genesisWith(t, 2, 2, keys, nil)
	led := mustLedger(t, g)
	chain := led.Chain()
	a := types.GovTx{ChainID: chain, Actions: []types.GovAction{{
		Kind: types.GovExtendRegistry, EventType: 9, Name: "left",
	}}}
	b := types.GovTx{ChainID: chain, Actions: []types.GovAction{{
		Kind: types.GovExtendRegistry, EventType: 10, Name: "right",
	}}}
	signAdmins(t, &a, keys)
	signAdmins(t, &b, keys)
	left, err := led.Transition(1, nil, []types.GovTx{a})
	if err != nil {
		t.Fatal(err)
	}
	right, err := led.Transition(1, nil, []types.GovTx{b})
	if err != nil {
		t.Fatal(err)
	}
	if left.Root() == right.Root() {
		t.Fatal("different pending revocations committed to the same root")
	}
}

func TestEpochRulesExhaustive(t *testing.T) {
	// Effect height is inclusion + delay. A revoke removes the seat at
	// that height and not before. The paired add keeps n = 3f+1.
	keys := mlKeys(t, 4)
	for _, delay := range []uint64{1, 2, 8} {
		g := genesisWith(t, 2, delay, keys, nil)
		led := mustLedger(t, g)
		chain := led.Chain()
		old := mustID(t, mustPub(t, keys[2]))
		spare := mlKeys(t, 1)[0]
		spareID := mustID(t, mustPub(t, spare))
		tx := types.GovTx{ChainID: chain, Actions: []types.GovAction{
			{Kind: types.GovRevokeKey, KeyID: old},
			{Kind: types.GovAddValidator, Key: mustPub(t, spare), Org: "founding-0", Address: "local"},
		}}
		signAdmins(t, &tx, keys)
		cur := led
		var err error
		cur, err = cur.Transition(1, nil, []types.GovTx{tx})
		if err != nil {
			t.Fatal(err)
		}
		for h := uint64(2); h <= delay; h++ {
			cur, err = cur.Transition(h, nil, nil)
			if err != nil {
				t.Fatal(err)
			}
			if !seated(t, cur, old) {
				t.Fatalf("delay %d height %d: key removed early", delay, h)
			}
		}
		cur, err = cur.Transition(delay+1, nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		if seated(t, cur, old) {
			t.Fatalf("delay %d: revoked key still seated", delay)
		}
		if !seated(t, cur, spareID) {
			t.Fatalf("delay %d: replacement was not seated", delay)
		}
		set, err := cur.ValidatorKeys()
		if err != nil || len(set) != 4 {
			t.Fatalf("delay %d: seat count %d", delay, len(set))
		}
	}
}

func TestWitnessRoundTrip(t *testing.T) {
	keys := mlKeys(t, 4)
	led := mustLedger(t, genesisWith(t, 2, 2, keys, nil))
	raw, err := led.Witness()
	if err != nil {
		t.Fatal(err)
	}
	back, err := RestoreWitness(raw)
	if err != nil {
		t.Fatal(err)
	}
	if back.Root() != led.Root() {
		t.Fatal("witness root changed")
	}
	got, err := back.ValidatorKeys()
	if err != nil {
		t.Fatal(err)
	}
	want, err := led.ValidatorKeys()
	if err != nil || len(got) != len(want) {
		t.Fatal(err)
	}
	for i := range want {
		if !got[i].Equal(want[i]) {
			t.Fatalf("seat %d", i)
		}
	}
}

func TestOneFounderRejected(t *testing.T) {
	if _, err := types.DefaultThreshold(1); err == nil {
		t.Fatal("one founder has a threshold")
	}
	keys := mlKeys(t, 4)
	founder := slhKeys(t, 1)
	pub := mustPub(t, founder[0])
	seats := make([]types.Seat, len(keys))
	grants := make([]types.Grant, len(keys))
	kinds := []uint16{types.EventShipmentDispatched, types.EventClearanceGranted, types.EventAccessLogin}
	for i, key := range keys {
		p := mustPub(t, key)
		seats[i] = types.Seat{Key: p, Org: "only", Address: "local"}
		grants[i] = types.Grant{Key: p, Org: "only", Roles: types.RoleKnown, EventTypes: kinds}
	}
	g := types.Genesis{
		Created: 1, EpochDelay: 2, Threshold: 1,
		Founders: []types.Founder{{Org: "only", Key: pub}},
		Seats:    seats, Grants: grants,
		Registry: []types.RegEntry{
			{Type: types.EventShipmentDispatched, Name: "shipment"},
			{Type: types.EventClearanceGranted, Name: "clearance"},
			{Type: types.EventAccessLogin, Name: "access"},
		},
	}
	if err := g.Sign(founder); err == nil {
		t.Fatal("a single founding organisation signed a genesis")
	}
}

func TestLoneRevokeOnFourRejected(t *testing.T) {
	keys := mlKeys(t, 4)
	g := genesisWith(t, 2, 2, keys, nil)
	led := mustLedger(t, g)
	tx := types.GovTx{ChainID: led.Chain(), Actions: []types.GovAction{{
		Kind: types.GovRevokeKey, KeyID: mustID(t, mustPub(t, keys[3])),
	}}}
	signAdmins(t, &tx, keys)
	if _, err := led.Transition(1, nil, []types.GovTx{tx}); !errors.Is(err, ErrTransition) {
		t.Fatalf("lone revoke on n=4 was accepted: %v", err)
	}
}

func TestRevokeBatchKeepsQuorum(t *testing.T) {
	keys := mlKeys(t, 4)
	g := genesisWith(t, 2, 2, keys, nil)
	led := mustLedger(t, g)
	chain := led.Chain()
	old := keys[3]
	oldPub := mustPub(t, old)
	neu := mlKeys(t, 1)[0]
	tx := types.GovTx{ChainID: chain, Actions: []types.GovAction{
		{Kind: types.GovRevokeKey, KeyID: mustID(t, oldPub)},
		{Kind: types.GovAddValidator, Key: mustPub(t, neu), Org: "founding-1", Address: "local"},
	}}
	signAdmins(t, &tx, keys)
	inc, err := led.Transition(1, nil, []types.GovTx{tx})
	if err != nil {
		t.Fatal(err)
	}
	mid, err := inc.Transition(2, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	before, err := mid.ValidatorKeys()
	if err != nil || len(before) != 4 || !before[3].Equal(oldPub) {
		t.Fatal("set changed before the effect height")
	}
	signers := []int{0, 1, 3}
	qc, err := types.AssembleQC(chain, 1, [32]byte{9}, []crypto.PrivateKey{keys[0], keys[1], keys[2], old}, signers)
	if err != nil {
		t.Fatal(err)
	}
	if err := qc.Verify(chain, before); err != nil {
		t.Fatal(err)
	}
	done, err := mid.Transition(3, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	after, err := done.ValidatorKeys()
	if err != nil || len(after) != 4 || !after[3].Equal(mustPub(t, neu)) {
		t.Fatal("replacement is not in the vacated index")
	}
	if err := qc.Verify(chain, after); err == nil {
		t.Fatal("previous certificate verified against the new set")
	}
	child, err := mid.VotersForChild(3)
	if err != nil {
		t.Fatal(err)
	}
	if len(child) != 4 || !child[3].Equal(mustPub(t, neu)) {
		t.Fatal("the new set does not vote from the effect height")
	}
}

func TestSevenRevokeThreeAndFounderFloor(t *testing.T) {
	keys := mlKeys(t, 7)
	g := genesisWith(t, 2, 1, keys, nil)
	led := mustLedger(t, g)
	chain := led.Chain()
	var drop []types.GovAction
	for _, idx := range []int{4, 5, 6} {
		drop = append(drop, types.GovAction{Kind: types.GovRevokeKey, KeyID: mustID(t, mustPub(t, keys[idx]))})
	}
	ok := types.GovTx{ChainID: chain, Actions: drop}
	signAdmins(t, &ok, keys)
	next, err := led.Transition(1, nil, []types.GovTx{ok})
	if err != nil {
		t.Fatal(err)
	}
	done, err := next.Transition(2, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	set, err := done.ValidatorKeys()
	if err != nil || len(set) != 4 {
		t.Fatalf("n=7 revoke three did not reach n=4: %v %d", err, len(set))
	}
	// Org founding-1 holds indexes 1, 3 and 5. Removing all three is n=4,
	// which is a legal size, and leaves one founding organisation.
	var wipe []types.GovAction
	for _, idx := range []int{1, 3, 5} {
		wipe = append(wipe, types.GovAction{Kind: types.GovRevokeKey, KeyID: mustID(t, mustPub(t, keys[idx]))})
	}
	bad := types.GovTx{ChainID: chain, Actions: wipe}
	signAdmins(t, &bad, keys)
	if _, err := led.Transition(1, nil, []types.GovTx{bad}); !errors.Is(err, ErrTransition) {
		t.Fatal("a batch that leaves one founding organisation was accepted")
	}
}

func ledgerWithReaders(t *testing.T, validators []crypto.PrivateKey, readerA, readerB, auditor crypto.PrivateKey) *Ledger {
	t.Helper()
	founders := slhKeys(t, 2)
	fpubs := make([]crypto.PublicKey, len(founders))
	for i, key := range founders {
		fpubs[i] = mustPub(t, key)
	}
	orgs := []string{"alpha", "beta"}
	seats := make([]types.Seat, len(validators))
	var grants []types.Grant
	kinds := []uint16{types.EventShipmentDispatched, types.EventClearanceGranted, types.EventAccessLogin}
	for i, key := range validators {
		pub := mustPub(t, key)
		org := orgs[i%2]
		seats[i] = types.Seat{Key: pub, Org: org, Address: "local"}
		grants = append(grants, types.Grant{Key: pub, Org: org, Roles: types.RoleKnown, EventTypes: append([]uint16(nil), kinds...)})
	}
	grants = append(grants,
		types.Grant{Key: mustPub(t, readerA), Org: "alpha", Roles: types.RoleReader},
		types.Grant{Key: mustPub(t, readerB), Org: "beta", Roles: types.RoleReader},
		types.Grant{Key: mustPub(t, auditor), Org: "alpha", Roles: types.RoleAuditor | types.RoleReader},
	)
	slices.SortFunc(grants, func(a, b types.Grant) int {
		aid, _ := a.Key.ID()
		bid, _ := b.Key.ID()
		return bytes.Compare(aid[:], bid[:])
	})
	g := types.Genesis{
		Created: 9, EpochDelay: 2, Threshold: 2,
		Founders: []types.Founder{{Org: "alpha", Key: fpubs[0]}, {Org: "beta", Key: fpubs[1]}},
		Seats:    seats, Grants: grants,
		Registry: []types.RegEntry{
			{Type: types.EventShipmentDispatched, Name: "shipment"},
			{Type: types.EventClearanceGranted, Name: "clearance"},
			{Type: types.EventAccessLogin, Name: "access"},
		},
	}
	if err := g.Sign(founders); err != nil {
		t.Fatal(err)
	}
	return mustLedger(t, g)
}

func genesisWith(t *testing.T, founders int, delay uint64, keys, founderKeys []crypto.PrivateKey) types.Genesis {
	t.Helper()
	if founderKeys == nil {
		founderKeys = slhKeys(t, founders)
	}
	fs := make([]types.Founder, len(founderKeys))
	for i, key := range founderKeys {
		org := "founding"
		if len(founderKeys) > 1 {
			org = []string{"founding-0", "founding-1", "founding-2"}[i]
		}
		fs[i] = types.Founder{Org: org, Key: mustPub(t, key)}
	}
	seats := make([]types.Seat, len(keys))
	grants := make([]types.Grant, len(keys))
	kinds := []uint16{types.EventShipmentDispatched, types.EventClearanceGranted, types.EventAccessLogin}
	for i, key := range keys {
		org := fs[0].Org
		if len(fs) > 1 {
			org = fs[i%len(fs)].Org
		}
		pub := mustPub(t, key)
		seats[i] = types.Seat{Key: pub, Org: org, Address: "local"}
		grants[i] = types.Grant{Key: pub, Org: org, Roles: types.RoleKnown, EventTypes: append([]uint16(nil), kinds...)}
	}
	slices.SortFunc(grants, func(a, b types.Grant) int {
		aid, _ := a.Key.ID()
		bid, _ := b.Key.ID()
		return bytes.Compare(aid[:], bid[:])
	})
	th, err := types.DefaultThreshold(len(fs))
	if err != nil {
		t.Fatal(err)
	}
	g := types.Genesis{
		Created: 1, EpochDelay: delay, Threshold: th,
		Founders: fs, Seats: seats, Grants: grants,
		Registry: []types.RegEntry{
			{Type: types.EventShipmentDispatched, Name: "shipment"},
			{Type: types.EventClearanceGranted, Name: "clearance"},
			{Type: types.EventAccessLogin, Name: "access"},
		},
	}
	if err := g.Sign(founderKeys); err != nil {
		t.Fatal(err)
	}
	return g
}

func eventFrom(t *testing.T, chain [32]byte, writer crypto.PrivateKey, nonce uint64, policy uint16) types.Event {
	t.Helper()
	pub := mustPub(t, writer)
	ev := types.Event{
		ChainID: chain, EventType: types.EventShipmentDispatched,
		Subject: []byte("crate"), Status: 1,
		DocHashes:   []types.DocHash{types.SHA3Doc([32]byte{byte(nonce)})},
		ClaimedTime: 10, WriterID: mustID(t, pub), Nonce: nonce, ReadPolicy: policy,
	}
	if err := ev.Sign(writer); err != nil {
		t.Fatal(err)
	}
	return ev
}

func signAdmins(t *testing.T, tx *types.GovTx, keys []crypto.PrivateKey) {
	t.Helper()
	if err := tx.SignAdmin(keys[0]); err != nil {
		t.Fatal(err)
	}
	if err := tx.SignAdmin(keys[1]); err != nil {
		t.Fatal(err)
	}
}

func seated(t *testing.T, led *Ledger, id [32]byte) bool {
	t.Helper()
	keys, err := led.ValidatorKeys()
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range keys {
		got, err := key.ID()
		if err != nil {
			t.Fatal(err)
		}
		if got == id {
			return true
		}
	}
	return false
}

func seatKey(t *testing.T, led *Ledger, index int) (crypto.PublicKey, [32]byte) {
	t.Helper()
	keys, err := led.ValidatorKeys()
	if err != nil {
		t.Fatal(err)
	}
	id, err := keys[index].ID()
	if err != nil {
		t.Fatal(err)
	}
	return keys[index], id
}

func mustLedger(t *testing.T, g types.Genesis) *Ledger {
	t.Helper()
	led, err := FromGenesis(g)
	if err != nil {
		t.Fatal(err)
	}
	return led
}

func mlKeys(t *testing.T, n int) []crypto.PrivateKey {
	t.Helper()
	out := make([]crypto.PrivateKey, n)
	for i := range out {
		k, err := crypto.GenerateMLDSA65()
		if err != nil {
			t.Fatal(err)
		}
		out[i] = k
	}
	return out
}

func slhKeys(t *testing.T, n int) []crypto.PrivateKey {
	t.Helper()
	out := make([]crypto.PrivateKey, n)
	for i := range out {
		k, err := crypto.GenerateSLHDSA(nil)
		if err != nil {
			t.Fatal(err)
		}
		out[i] = k
	}
	return out
}

func mustPub(t *testing.T, key crypto.PrivateKey) crypto.PublicKey {
	t.Helper()
	pub, err := key.Public()
	if err != nil {
		t.Fatal(err)
	}
	return pub
}

func mustID(t *testing.T, pub crypto.PublicKey) [32]byte {
	t.Helper()
	id, err := pub.ID()
	if err != nil {
		t.Fatal(err)
	}
	return id
}
