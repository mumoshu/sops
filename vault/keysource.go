package vault //import "go.mozilla.org/sops/vault"

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"go.mozilla.org/sops/logging"

	"github.com/hashicorp/vault/api"
	"github.com/sirupsen/logrus"
)

var log *logrus.Logger

func init() {
	log = logging.NewLogger("VAULT")
}

// MasterKey is a GCP KMS key used to encrypt and decrypt sops' data key.
type MasterKey struct {
	KeyName      string
	EncryptedKey string
	CreationDate time.Time
}

// EncryptedDataKey returns the encrypted data key this master key holds
func (key *MasterKey) EncryptedDataKey() []byte {
	return []byte(key.EncryptedKey)
}

// SetEncryptedDataKey sets the encrypted data key for this master key
func (key *MasterKey) SetEncryptedDataKey(enc []byte) {
	key.EncryptedKey = string(enc)
}

// Encrypt takes a sops data key, encrypts it with GCP KMS and stores the result in the EncryptedKey field
func (key *MasterKey) Encrypt(dataKey []byte) error {
	vaultClient, err := key.createVaultClient()
	if err != nil {
		log.WithField("keyName", key.KeyName).Info("Encryption failed")
		return fmt.Errorf("Cannot create Vault client: %v", err)
	}
	encryptPath := fmt.Sprintf("/transit/encrypt/%s", key.KeyName)
	data := map[string]interface{}{"plaintext": string(dataKey)}
	secret, err := vaultClient.Logical().Write(encryptPath, data)
	if err != nil {
		log.WithField("keyName", key.KeyName).Info("Encryption failed")
		return fmt.Errorf("Failed to call Vault: %v", err)
	}
	log.WithField("keyName", key.KeyName).Info("Encryption succeeded")
	cipherText, ok := secret.Data["ciphertext"].(string)
	if !ok {
		log.WithField("keyName", key.KeyName).Info("Decryption failed")
		return errors.New("Error encrypting key: no ciphertecxt contained in the response from Vault")
	}
	key.EncryptedKey = cipherText
	return nil
}

// EncryptIfNeeded encrypts the provided sops' data key and encrypts it if it hasn't been encrypted yet
func (key *MasterKey) EncryptIfNeeded(dataKey []byte) error {
	if key.EncryptedKey == "" {
		return key.Encrypt(dataKey)
	}
	return nil
}

// Decrypt decrypts the EncryptedKey field with Vault and returns the result.
func (key *MasterKey) Decrypt() ([]byte, error) {
	vaultClient, err := key.createVaultClient()
	if err != nil {
		log.WithField("keyName", key.KeyName).Info("Decryption failed")
		return nil, fmt.Errorf("Cannot create Vault client: %v", err)
	}

	decryptPath := fmt.Sprintf("/transit/decrypt/%s", key.KeyName)
	data := map[string]interface{}{"ciphertext": key.EncryptedKey}
	secret, err := vaultClient.Logical().Write(decryptPath, data)
	if err != nil {
		log.WithField("keyName", key.KeyName).Info("Decryption failed")
		return nil, fmt.Errorf("Error decrypting key: %v", err)
	}
	plaintext, ok := secret.Data["plaintext"].(string)
	if !ok {
		log.WithField("keyName", key.KeyName).Info("Decryption failed")
		return nil, errors.New("Error decrypting key: no plaintext contained in the response from Vault")
	}
	return []byte(plaintext), nil
}

// NeedsRotation returns whether the data key needs to be rotated or not.
func (key *MasterKey) NeedsRotation() bool {
	return time.Since(key.CreationDate) > (time.Hour * 24 * 30 * 6)
}

// ToString converts the key to a string representation
func (key *MasterKey) ToString() string {
	return key.KeyName
}

// NewMasterKeyFromKeyName takes a Vault key name string and returns a new MasterKey for that
func NewMasterKeyFromKeyName(keyName string) *MasterKey {
	k := &MasterKey{}
	keyName = strings.Replace(keyName, " ", "", -1)
	k.KeyName = keyName
	k.CreationDate = time.Now().UTC()
	return k
}

// MasterKeysFromKeyNameString takes a comma separated list of Vault key names and returns a slice of new MasterKeys for them
func MasterKeysFromKeyNameString(keyName string) []*MasterKey {
	var keys []*MasterKey
	if keyName == "" {
		return keys
	}
	for _, s := range strings.Split(keyName, ",") {
		keys = append(keys, NewMasterKeyFromKeyName(s))
	}
	return keys
}

func (key MasterKey) createVaultClient() (*api.Client, error) {
	config := api.DefaultConfig()

	client, err := api.NewClient(config)
	if err != nil {
		return nil, err
	}

	return client, nil
}

// ToMap converts the MasterKey to a map for serialization purposes
func (key MasterKey) ToMap() map[string]interface{} {
	out := make(map[string]interface{})
	out["key_name"] = key.KeyName
	out["enc"] = key.EncryptedKey
	out["created_at"] = key.CreationDate.UTC().Format(time.RFC3339)
	return out
}
