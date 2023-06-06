package typeFFFF

import (
	"testing"
)

func TestKeyStore(t *testing.T) {
	store := EmptyKeyStore()

	store.AddIntegrityKey(createRandomIntegrityKey())
	store.AddIntegrityKey(createRandomIntegrityKey())
	if store.Count() != 2 {
		t.Fatal("Mismatch count")
	}

	_, _ = store.PopKey()
	if store.Count() != 1 {
		t.Fatal("Mismatch count")
	}

	_, _ = store.PopKey()
	if store.Count() != 0 {
		t.Fatal("Mismatch count")
	}

	_, err := store.PopKey()
	if err == nil {
		t.Fatal("Expected pop failure")
	}
}
