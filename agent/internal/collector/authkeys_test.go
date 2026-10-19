package collector

import (
	"testing"
	"time"
)

// Throwaway keys generated for these tests; expected values come from `ssh-keygen -lf`.
const (
	fixtureEd25519 = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGHDHh63eGl0t3JJqE1tS1PFQsYSYdCv4PK+h/BO1/jX fixture-ed25519"
	fixtureRSA     = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCrnNdnpdaoViayOgv9OxGImwVw+UuiysfIX6ggBxadxRuBk++Zowv1KzcmnHcg7K1/O4As4MGIDHHA2dK7o+yWnZ2aU4pUOt9KF/ucQ1jird7ZBDWLS3WP7v00iWOM7n+jklMJ+uVLAmdUZ2QhNO9AzfquyCGovEegODuIdcBwF8mJzpnjZ1OBFfTESaZ7HDX2BPsoFTH7Fww3Ocrtvz6RaQB5dkdcy8QrrueAwUc6Oa4PLT1t4FC5Y5vZHiFniLN/6OPYlSecdCBESQ/ufyCfnhw4rC6iC47EozPi/Z3eOBKnAMBOa47shpe8h83QkAmXOYWpirXFETMeEwbZAmqu06XG27c1PS2u9uiFRmFoxEjxkyxWL6CrV9CFYjbrTyIkyVq65xJyg75LVkvnESoNmLT5aV1BsS/0MkQE1vWgjcWQYLs54qdsDkn2l6Y2Hu0qumFtcvNI/23qdGYv35L4yafja13ik4H9empcKiRs1nk34ArIomkCCXwe8ddcpws= fixture-rsa"
	fixtureECDSA   = "ecdsa-sha2-nistp384 AAAAE2VjZHNhLXNoYTItbmlzdHAzODQAAAAIbmlzdHAzODQAAABhBJX9/zr8KgeKPpeFGDpb3ds5bgpomqVgsYynSwRoxaJouArdxYtZNBKsaV9t7reM0H6f4LjZix9OcRxJdRKqyT0odwaD70iCOTZ2tip5l9dAUl6FOk8ntxOyzUuSeER+iA== fixture-ecdsa"
)

func TestParseAuthorizedKeysMatchesSSHKeygen(t *testing.T) {
	content := "# comment\n\n" + fixtureEd25519 + "\n" +
		`expiry-time="20261019182949Z",no-agent-forwarding ` + fixtureRSA + "\n" +
		`command="echo hi there",from="10.0.0.0/8" ` + fixtureECDSA + "\n" +
		"garbage line\nssh-ed25519 !!!notbase64 x\n"
	keys := ParseAuthorizedKeys(content)
	if len(keys) != 3 {
		t.Fatalf("want 3 keys, got %d: %+v", len(keys), keys)
	}
	want := []struct {
		typ, fp, comment string
		bits             int
		opts             bool
	}{
		{"ssh-ed25519", "SHA256:ia3SozCqn3fFIGfMANOu9QDmg6Q7B5pS49cN/W2zDX8", "fixture-ed25519", 256, false},
		{"ssh-rsa", "SHA256:zBdFQvPYbfk0oUAM9BkcCJEE+rjanmmtPwhQ7SvcDhg", "fixture-rsa", 3072, true},
		{"ecdsa-sha2-nistp384", "SHA256:cIASJVl9UbRlD3SXP4XXLRBzdQLN1o/NHf6Jhjoq7yw", "fixture-ecdsa", 384, true},
	}
	for i, w := range want {
		k := keys[i]
		if k.Type != w.typ || k.Fingerprint != w.fp || k.Comment != w.comment || k.Bits != w.bits || k.Options != w.opts {
			t.Errorf("key %d: got %+v want %+v", i, k, w)
		}
	}
	if keys[0].ExpiresAt != nil || keys[2].ExpiresAt != nil {
		t.Error("only the RSA key has an expiry")
	}
	if exp := keys[1].ExpiresAt; exp == nil || !exp.Equal(time.Date(2026, 10, 19, 18, 29, 49, 0, time.UTC)) {
		t.Errorf("expiry %v", exp)
	}
}

func TestDiffKeys(t *testing.T) {
	a := AuthKey{Type: "ssh-ed25519", Fingerprint: "SHA256:a"}
	b := AuthKey{Type: "ssh-rsa", Fingerprint: "SHA256:b"}
	c := AuthKey{Type: "ssh-ed25519", Fingerprint: "SHA256:c"}
	added, removed := DiffKeys([]AuthKey{a, b}, []AuthKey{a, c})
	if len(added) != 1 || added[0].Fingerprint != "SHA256:c" || len(removed) != 1 || removed[0].Fingerprint != "SHA256:b" {
		t.Fatalf("added %+v removed %+v", added, removed)
	}
}

func TestDiffFilesReportsKeys(t *testing.T) {
	path := "/root/.ssh/authorized_keys"
	a := AuthKey{Type: "ssh-ed25519", Fingerprint: "SHA256:a", Comment: "me"}
	tmp := AuthKey{Type: "ssh-rsa", Fingerprint: "SHA256:t"}
	prev := map[string]FileState{path: {Hash: "1", Keys: []AuthKey{a}, KeysParsed: true}}
	now := map[string]FileState{path: {Hash: "2", Keys: []AuthKey{a, tmp}, KeysParsed: true}}
	ev := DiffFiles(prev, now, time.Now())
	if len(ev) != 1 {
		t.Fatalf("events %+v", ev)
	}
	added, ok := ev[0].Metadata["addedKeys"].([]AuthKey)
	if !ok || len(added) != 1 || added[0].Fingerprint != "SHA256:t" {
		t.Errorf("addedKeys %+v", ev[0].Metadata["addedKeys"])
	}
	if _, ok := ev[0].Metadata["removedKeys"]; ok {
		t.Error("nothing was removed")
	}

	// Baseline from an older agent has no key list: do not claim every key is new.
	legacy := map[string]FileState{path: {Hash: "1"}}
	if ev := DiffFiles(legacy, now, time.Now()); ev[0].Metadata["addedKeys"] != nil {
		t.Errorf("legacy baseline must not report keys: %+v", ev[0].Metadata)
	}
}
