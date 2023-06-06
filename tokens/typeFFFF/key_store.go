package typeFFFF

import (
	"encoding/hex"
	"errors"
)

var (
	ErrNoIntegrityKeys = errors.New("no integrity keys available")
)

type KeyStore struct {
	// XXX(caw): this is a terrible set implementation, but it works
	store map[string]IntegrityKey
}

func EmptyKeyStore() *KeyStore {
	return &KeyStore{
		store: make(map[string]IntegrityKey),
	}
}

func (k *KeyStore) AddIntegrityKey(key IntegrityKey) {
	index := hex.EncodeToString(key.publicKey)
	k.store[index] = key
}

func (k *KeyStore) PopKey() (IntegrityKey, error) {
	if len(k.store) == 0 {
		return IntegrityKey{}, ErrNoIntegrityKeys
	}
	var index string
	var key IntegrityKey
	for candidateKey := range k.store {
		index = candidateKey
		key = k.store[candidateKey]
		break
	}
	delete(k.store, index)
	return key, nil
}

func (k *KeyStore) Count() int {
	return len(k.store)
}
