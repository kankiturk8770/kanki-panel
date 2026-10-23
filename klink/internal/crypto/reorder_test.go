package crypto

import "testing"

// A packet sealed just before the sender rekeys can arrive after the first
// packet of the new epoch on UDP; it must still be accepted.
func TestPreviousEpochPacketAcceptedAfterRekey(t *testing.T) {
	_, clientOut, serverIn, _, _ := completeHandshake(t)
	late, _, _ := clientOut.Seal([]byte("late epoch zero"))
	clientOut.Rekey()
	early, _, _ := clientOut.Seal([]byte("epoch one"))
	if _, _, epoch, err := serverIn.Open(early); err != nil || epoch != 1 {
		t.Fatalf("epoch one: %v %d", err, epoch)
	}
	plain, _, epoch, err := serverIn.Open(late)
	if err != nil || epoch != 0 || string(plain) != "late epoch zero" {
		t.Fatalf("delayed previous-epoch packet rejected: %v", err)
	}
	// Two epochs back is never accepted.
	clientOut.Rekey()
	two, _, _ := clientOut.Seal([]byte("epoch two"))
	if _, _, _, err := serverIn.Open(two); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := serverIn.Open(late); err == nil {
		t.Fatal("packet from two epochs ago accepted")
	}
}

func TestSealToAppends(t *testing.T) {
	_, clientOut, serverIn, _, _ := completeHandshake(t)
	prefix := []byte("hdr")
	out, _, err := clientOut.SealTo(append([]byte(nil), prefix...), []byte("body"))
	if err != nil || string(out[:3]) != "hdr" {
		t.Fatalf("prefix lost: %v", err)
	}
	if plain, _, _, err := serverIn.Open(out[3:]); err != nil || string(plain) != "body" {
		t.Fatalf("open: %v", err)
	}
}

func TestReplayWindowNewest(t *testing.T) {
	var w ReplayWindow
	if newest, err := w.CheckNewest(5); err != nil || !newest {
		t.Fatal("first packet should be newest")
	}
	if newest, err := w.CheckNewest(3); err != nil || newest {
		t.Fatal("older packet reported as newest")
	}
}
