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

// TODO probably return types will need to be changed
func HideAttributes(attributes []*attribute.Attribute) ([]uint32, []byte, error) {

	hiddenAttrs, salt, err := zkdil.HideAttributes(attributes)
	if err != nil {
		return nil, nil, err
	}

	return hiddenAttrs, salt, nil
}
