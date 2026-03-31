package gabikeys

import (
	"encoding/xml"
	"io"
	"os"
	"time"

	"github.com/AVecsi/pq-gabi/internal/common"
)

const (
	XMLHeader = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"no\"?>\n"
)

// PublicKey is the high-level, crypto-agnostic interface for an issuer public key.
type PublicKey interface {
	GetCounter() uint
	GetExpiryDate() int64
	GetIssuer() string
	SetIssuer(issuer string)
	ValidAt(t time.Time) bool
	WriteTo(writer io.Writer) (int64, error)
	WriteToFile(filename string, forceOverwrite bool) (int64, error)
	Print() error
}

// PrivateKey is the high-level, crypto-agnostic interface for an issuer private key.
type PrivateKey interface {
	GetCounter() uint
	GetExpiryDate() int64
	ValidAt(t time.Time) bool
	WriteTo(writer io.Writer) (int64, error)
	WriteToFile(filename string, forceOverwrite bool) (int64, error)
	Print() error
}

// BasePublicKey holds the high-level fields shared by all public key implementations.
// Concrete key types in crypto-specific packages embed this.
type BasePublicKey struct {
	XMLName    xml.Name `xml:"http://www.zurich.ibm.com/security/idemix IssuerPublicKey"`
	Counter    uint     `xml:"Counter"`
	ExpiryDate int64    `xml:"ExpiryDate"`
	Issuer     string   `xml:"-"`
}

func (pk *BasePublicKey) GetCounter() uint        { return pk.Counter }
func (pk *BasePublicKey) GetExpiryDate() int64    { return pk.ExpiryDate }
func (pk *BasePublicKey) GetIssuer() string       { return pk.Issuer }
func (pk *BasePublicKey) SetIssuer(issuer string) { pk.Issuer = issuer }
func (pk *BasePublicKey) ValidAt(t time.Time) bool {
	return t.Before(time.Unix(pk.ExpiryDate, 0))
}

// BasePrivateKey holds the high-level fields shared by all private key implementations.
// Concrete key types in crypto-specific packages embed this.
type BasePrivateKey struct {
	XMLName    xml.Name `xml:"http://www.zurich.ibm.com/security/idemix IssuerPrivateKey"`
	Counter    uint     `xml:"Counter"`
	ExpiryDate int64    `xml:"ExpiryDate"`
}

func (sk *BasePrivateKey) GetCounter() uint     { return sk.Counter }
func (sk *BasePrivateKey) GetExpiryDate() int64 { return sk.ExpiryDate }
func (sk *BasePrivateKey) ValidAt(t time.Time) bool {
	return t.Before(time.Unix(sk.ExpiryDate, 0))
}

// writeKeyTo is a shared helper for writing XML-serialized keys.
func WriteKeyTo(header []byte, body []byte, writer io.Writer) (int64, error) {
	n1, err := writer.Write(header)
	if err != nil {
		return 0, err
	}
	n2, err := writer.Write(body)
	return int64(n1 + n2), err
}

// WriteKeyToFile is a shared helper for writing a key to a file.
func WriteKeyToFile(filename string, forceOverwrite bool, writeFn func(io.Writer) (int64, error)) (int64, error) {
	var f *os.File
	var err error
	if forceOverwrite {
		f, err = os.Create(filename)
	} else {
		f, err = os.OpenFile(filename, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0600)
	}
	if err != nil {
		return 0, err
	}
	defer common.Close(f)
	return writeFn(f)
}
