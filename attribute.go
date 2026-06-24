// pq_gabi/attribute.go
package gabi

import (
	"github.com/AVecsi/pq-gabi/attribute"
	"github.com/AVecsi/pq-gabi/big"
	"github.com/AVecsi/pq-gabi/internal/common"
	"github.com/AVecsi/pq-gabi/internal/zkdil"
)

// Re-export Attribute so callers can use pqgabi.Attribute
type Attribute = attribute.Attribute

var NewAttribute = attribute.NewAttribute

// GenerateSecretAttribute generates secret attribute used prove ownership and links between credentials from the same user.
func GenerateSecretAttribute() (*big.Int, error) {
	//12*3 byte for lazy field elements
	return common.RandomBigInt(288)
}

func GenerateSalt() ([]byte, error) {

	salt, err := zkdil.GenerateSalt()
	if err != nil {
		return nil, err
	}

	return salt, nil
}

// Commit produces an opaque issuance commitment to the hidden attributes (the
// user link secret) and the opaque opening the client keeps and later passes to
// NewCredential. Both are scheme-defined; the protocol layer treats them as
// opaque bytes.
func Commit(attributes []*attribute.Attribute) ([]byte, []byte, error) {

	commitment, opening, err := zkdil.Commit(attributes)
	if err != nil {
		return nil, nil, err
	}

	return commitment, opening, nil
}

func CombineHiddenPublic(hiddenAttrsHash []byte, publicAttributes []*attribute.Attribute) []uint32 {
	return zkdil.CombineHiddenPublic(hiddenAttrsHash, publicAttributes)
}
