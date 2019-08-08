package vault

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestVaultKeySourceFromString(t *testing.T) {
	s := "key1,key2"
	ks := MasterKeysFromKeyNameString(s)
	k1 := ks[0]
	k2 := ks[1]
	expectedKeyName1 := "key1"
	expectedKeyName2 := "key2"
	if k1.KeyName != expectedKeyName1 {
		t.Errorf("KeyName mismatch. Expected %s, found %s", expectedKeyName1, k1.KeyName)
	}
	if k2.KeyName != expectedKeyName2 {
		t.Errorf("KeyName mismatch. Expected %s, found %s", expectedKeyName2, k2.KeyName)
	}
}

func TestKeyToMap(t *testing.T) {
	key := MasterKey{
		CreationDate: time.Date(2016, time.October, 31, 10, 0, 0, 0, time.UTC),
		KeyName:      "foo",
		EncryptedKey: "this is encrypted",
	}
	assert.Equal(t, map[string]interface{}{
		"key_name": "foo",
		"enc":         "this is encrypted",
		"created_at":  "2016-10-31T10:00:00Z",
	}, key.ToMap())
}
