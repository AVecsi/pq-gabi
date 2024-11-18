package gabikeys

import (
	"encoding/xml"
	"io"
	"os"
	"time"

	"github.com/BeardOfDoom/pq-gabi/algebra"
	"github.com/BeardOfDoom/pq-gabi/internal/common"
	"github.com/BeardOfDoom/pq-gabi/zkDilithium"
)

type (
	// PublicKey represents an issuer's public key.
	PublicKey struct {
		XMLName    xml.Name     `xml:"http://www.zurich.ibm.com/security/idemix IssuerPublicKey"`
		Counter    uint         `xml:"Counter"`
		ExpiryDate int64        `xml:"ExpiryDate"`
		Rho        []byte       `xml:"Elements>rho"`
		T          *algebra.Vec `xml:"Elements>t"`
		//EpochLength EpochLength `xml:"Features"` TODO
		//ECDSAString string `xml:"ECDSA,omitempty"` TODO

		//ECDSA *ecdsa.PublicKey `xml:"-"` TODO
		//Params *SystemParameters `xml:"-"` TODO
		Issuer string `xml:"-"`
	}

	// PrivateKey represents an issuer's private key.
	PrivateKey struct {
		XMLName    xml.Name     `xml:"http://www.zurich.ibm.com/security/idemix IssuerPrivateKey"`
		Counter    uint         `xml:"Counter"`
		ExpiryDate int64        `xml:"ExpiryDate"`
		CNS        []byte       `xml:"Elements>CNS"` //challengeNonceSeed
		S1         *algebra.Vec `xml:"Elements>s1"`
		S2         *algebra.Vec `xml:"Elements>s2"`
		//ECDSAString string       `xml:"ECDSA,omitempty"` TODO

		//ECDSA *ecdsa.PrivateKey `xml:"-"` TODO
		//Order *big.Int          `xml:"-"`
	}

	//EpochLength int TODO
)

const (
	//XMLHeader can be a used as the XML header when writing keys in XML format.
	XMLHeader = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"no\"?>\n"
	// DefaultEpochLength is the default epoch length for public keys.
	//DefaultEpochLength = 432000 TODO
)

// NewPrivateKey creates a new issuer private key using the provided parameters.
func NewPrivateKey(cns []byte, s1, s2 *algebra.Vec, counter uint, expiryDate time.Time) (*PrivateKey, error) {
	sk := PrivateKey{
		CNS:        cns,
		S1:         s1,
		S2:         s2,
		Counter:    counter,
		ExpiryDate: expiryDate.Unix(),
	}

	//TODO
	// if err := sk.parseRevocationKey(); err != nil {
	// 	return nil, err
	// }

	return &sk, nil
}

// NewPrivateKeyFromXML creates a new issuer private key using the XML data
// provided.
func NewPrivateKeyFromXML(xmlInput string, demo bool) (*PrivateKey, error) {
	privk := &PrivateKey{}
	err := xml.Unmarshal([]byte(xmlInput), privk)
	if err != nil {
		return nil, err
	}

	if !demo {
		// Do some sanity checks on the key data
		if err := privk.Validate(); err != nil {
			return nil, err
		}
	}

	//TODO
	// if err := privk.parseRevocationKey(); err != nil {
	// 	return nil, err
	// }

	return privk, nil
}

// NewPrivateKeyFromFile creates a new issuer private key from an XML file.
func NewPrivateKeyFromFile(filename string, demo bool) (*PrivateKey, error) {
	f, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer common.Close(f)

	b, err := io.ReadAll(f)
	if err != nil {
		return nil, err
	}

	return NewPrivateKeyFromXML(string(b), demo)
}

func (privk *PrivateKey) Validate() error {
	//TODO implement validation for S1 and S2 to validate the polynom coefficients are elements of the field
	return nil
}

// Print prints the key to stdout.
func (privk *PrivateKey) Print() error {
	_, err := privk.WriteTo(os.Stdout)
	return err
}

// WriteTo writes the XML-serialized public key to the given writer.
func (privk *PrivateKey) WriteTo(writer io.Writer) (int64, error) {
	// Write the standard XML header
	numHeaderBytes, err := writer.Write([]byte(XMLHeader))
	if err != nil {
		return 0, err
	}

	// And the actual XML body (with indentation)
	b, err := xml.MarshalIndent(privk, "", "   ")
	if err != nil {
		return int64(numHeaderBytes), err
	}
	numBodyBytes, err := writer.Write(b)
	return int64(numHeaderBytes + numBodyBytes), err
}

// WriteToFile writes the private key to an XML file. If any existing file with
// the same filename should be overwritten, set forceOverwrite to true.
func (privk *PrivateKey) WriteToFile(filename string, forceOverwrite bool) (int64, error) {
	var f *os.File
	var err error
	if forceOverwrite {
		f, err = os.Create(filename)
	} else {
		// This should return an error if the file already exists
		f, err = os.OpenFile(filename, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0600)
	}
	if err != nil {
		return 0, err
	}
	defer common.Close(f)

	return privk.WriteTo(f)
}

//TODO
// func (privk *PrivateKey) parseRevocationKey() error {
// 	if privk.ECDSA != nil || !privk.RevocationSupported() {
// 		return nil
// 	}
// 	bts, err := base64.StdEncoding.DecodeString(privk.ECDSAString)
// 	if err != nil {
// 		return err
// 	}
// 	key, err := signed.UnmarshalPrivateKey(bts)
// 	if err != nil {
// 		return err
// 	}
// 	privk.ECDSA = key
// 	return nil
// }

// func (privk *PrivateKey) RevocationSupported() bool {
// 	return len(privk.ECDSAString) > 0
// }

// func GenerateRevocationKeypair(privk *PrivateKey, pubk *PublicKey) error {
// 	if pubk.RevocationSupported() || privk.RevocationSupported() {
// 		return errors.New("revocation parameters already present")
// 	}

// 	key, err := signed.GenerateKey()
// 	if err != nil {
// 		return err
// 	}
// 	dsabts, err := signed.MarshalPrivateKey(key)
// 	if err != nil {
// 		return err
// 	}
// 	pubdsabts, err := signed.MarshalPublicKey(&key.PublicKey)
// 	if err != nil {
// 		return err
// 	}

// 	privk.ECDSAString = base64.StdEncoding.EncodeToString(dsabts)
// 	privk.ECDSA = key
// 	pubk.ECDSAString = base64.StdEncoding.EncodeToString(pubdsabts)
// 	pubk.ECDSA = &key.PublicKey
// 	pubk.G = common.RandomQR(pubk.N)
// 	pubk.H = common.RandomQR(pubk.N)

// 	return nil
// }

// NewPublicKey creates and returns a new public key based on the provided parameters.
func NewPublicKey(rho []byte, t *algebra.Vec, counter uint, expiryDate time.Time) (*PublicKey, error) {
	pk := &PublicKey{
		Counter:    counter,
		ExpiryDate: expiryDate.Unix(),
		Rho:        rho,
		T:          t,
	}

	//TODO
	// if err := pk.parseRevocationKey(); err != nil {
	// 	return nil, err
	// }
	return pk, nil
}

// NewPublicKeyFromBytes creates a new issuer public key using the XML data
// provided.
func NewPublicKeyFromBytes(bts []byte) (*PublicKey, error) {
	// TODO: this might fail in the future. The DefaultSystemParameters and the
	// public key might not match!
	pubk := &PublicKey{}
	err := xml.Unmarshal(bts, pubk)
	if err != nil {
		return nil, err
	}

	//TODO
	// if err = pubk.parseRevocationKey(); err != nil {
	// 	return nil, err
	// }
	return pubk, nil
}

func NewPublicKeyFromXML(xmlInput string) (*PublicKey, error) {
	return NewPublicKeyFromBytes([]byte(xmlInput))
}

// NewPublicKeyFromFile creates a new issuer public key from an XML file.
func NewPublicKeyFromFile(filename string) (*PublicKey, error) {
	f, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer common.Close(f)
	pubk := &PublicKey{}

	b, err := io.ReadAll(f)
	if err != nil {
		return nil, err
	}

	err = xml.Unmarshal(b, pubk)
	if err != nil {
		return nil, err
	}

	//TODO
	// if err = pubk.parseRevocationKey(); err != nil {
	// 	return nil, err
	// }
	return pubk, nil
}

// func (pubk *PublicKey) parseRevocationKey() error {
// 	if pubk.ECDSA != nil || !pubk.RevocationSupported() {
// 		return nil
// 	}
// 	bts, err := base64.StdEncoding.DecodeString(pubk.ECDSAString)
// 	if err != nil {
// 		return err
// 	}
// 	dsakey, err := signed.UnmarshalPublicKey(bts)
// 	if err != nil {
// 		return err
// 	}
// 	pubk.ECDSA = dsakey
// 	return nil
// }

// func (pubk *PublicKey) RevocationSupported() bool {
// 	return pubk.G != nil && pubk.H != nil && len(pubk.ECDSAString) > 0
// }

// Print prints the key to stdout.
func (pubk *PublicKey) Print() error {
	_, err := pubk.WriteTo(os.Stdout)
	return err
}

// WriteTo writes the XML-serialized public key to the given writer.
func (pubk *PublicKey) WriteTo(writer io.Writer) (int64, error) {
	// Write the standard XML header
	numHeaderBytes, err := writer.Write([]byte(XMLHeader))
	if err != nil {
		return 0, err
	}

	// And the actual XML body (with indentation)
	b, err := xml.MarshalIndent(pubk, "", "   ")
	if err != nil {
		return int64(numHeaderBytes), err
	}
	numBodyBytes, err := writer.Write(b)
	return int64(numHeaderBytes + numBodyBytes), err
}

// WriteToFile writes the public key to an XML file. If any existing file with
// the same filename should be overwritten, set forceOverwrite to true.
func (pubk *PublicKey) WriteToFile(filename string, forceOverwrite bool) (int64, error) {
	var f *os.File
	var err error
	if forceOverwrite {
		f, err = os.Create(filename)
	} else {
		// This should return an error if the file already exists
		f, err = os.OpenFile(filename, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0644)
	}
	if err != nil {
		return 0, err
	}
	defer common.Close(f)

	return pubk.WriteTo(f)
}

// GenerateKeyPair generates a private/public keypair for an Issuer
func GenerateKeyPair(seed []byte, counter uint, expiryDate time.Time) (*PrivateKey, *PublicKey, error) {
	rho, t, cns, s1, s2, err := zkDilithium.Gen(seed)
	if err != nil {
		return nil, nil, err
	}

	priv := &PrivateKey{
		CNS:        cns,
		S1:         s1,
		S2:         s2,
		Counter:    counter,
		ExpiryDate: expiryDate.Unix(),
	}

	//TODO
	// if err = priv.parseRevocationKey(); err != nil {
	// 	return nil, nil, err
	// }

	// compute n
	pubk := &PublicKey{
		Rho:        rho,
		T:          t,
		Counter:    counter,
		ExpiryDate: expiryDate.Unix(),
	}

	//TODO
	// if err = pubk.parseRevocationKey(); err != nil {
	// 	return nil, nil, err
	// }

	// if err = GenerateRevocationKeypair(priv, pubk); err != nil {
	// 	return nil, nil, err
	// }

	return priv, pubk, nil
}
