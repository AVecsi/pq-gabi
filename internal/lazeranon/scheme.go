//go:build lazer

// Package lazeranon is the lazer (Falcon-512 / LNP) anonymous-credentials
// backend behind the gabi scheme contract. It is selected by building with
// -tags lazer; the default build uses zkDilithium.
//
// Model (Option C, IRMA-faithful): the message is split into the user's secret
// (the first lazer.AnonNumSecret blocks, = the hidden/link attribute) and the
// issuer-controlled blocks (metadata + public attributes). The user commits
// ONLY the secret at Commit time; the issuer contributes its blocks in
// CombineHiddenPublic + Sign by homomorphically adding AM_pub*m_pub to the
// commitment and blind-signing the result. The user's commitment structurally
// excludes the issuer columns, so the issuer fully certifies its blocks. At
// disclosure any subset of issuer blocks may be revealed; the secret stays
// hidden. The opaque opening carries the secret commitment randomness r so a
// credential can be disclosed after the C user-state has been torn down.
package lazeranon

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"

	"github.com/AVecsi/pq-gabi/attribute"
	"github.com/AVecsi/pq-gabi/credtypes"
	"github.com/AVecsi/pq-gabi/gabikeys"
	"github.com/go-errors/errors"

	"XXX1.org/lazer"
)

// Block layout, mirroring the lazer C parameters:
//   blocks [0, nSecret)  -> user secret (link attribute), committed by user
//   blocks [nSecret, ..) -> issuer attributes (metadata + public), 1 each
// The total block count is dynamic (chosen by tier); see nmsgBytes / the lazer
// tier helpers.
const (
	nSecret    = lazer.AnonNumSecret // 4
	blockBytes = 8                   // 64 bits per block
)

// nmsgBytes is the full message length (secret + the tier's issuer capacity).
func nmsgBytes(tier int) int {
	return (nSecret + lazer.AnonTierNpub(tier)) * blockBytes
}

// lazerSignature is the credtypes.Signature for the lazer backend. It carries
// the issuer's Falcon public key (needed for disclosure and verification), the
// lazer blind signature, the credential's tier, and the opaque opening (saved
// randomness r || secret). The opening is stored here so it persists with a
// serialized signature and is available on credential reload, mirroring
// zkDilithium's IssuanceSalt.
type lazerSignature struct {
	Pk       []byte `json:"pk"`
	Blindsig []byte `json:"blindsig"`
	Tier     int    `json:"tier"`
	Opening  []byte `json:"opening,omitempty"`
}

// --- credtypes.Signature ---

func (s *lazerSignature) Verify() (bool, error) {
	return len(s.Blindsig) > 0 && len(s.Pk) == lazer.AnonPubkeyLen, nil
}

// CreateProof is unused by the lazer backend: the disclosure proof is produced
// by Credential.CreateDisclosure (which has the opening, the public attribute
// values, and the disclosed indices), not from the signature alone.
func (s *lazerSignature) CreateProof() (credtypes.SignatureProof, error) {
	return nil, errors.New("lazeranon: CreateProof is not used; disclosure proof is built in CreateDisclosure")
}

func ParseSignature(data []byte) (credtypes.Signature, error) {
	var sig lazerSignature
	if err := json.Unmarshal(data, &sig); err != nil {
		return nil, err
	}
	return &sig, nil
}

// Commit commits to the user's secret (the hidden/link attributes), hashed to
// the nSecret secret blocks. The issuer attributes are NOT committed here; they
// are added by the issuer in CombineHiddenPublic + Sign. Returns the commitment
// (masked message) and the opaque opening the client stores.
func Commit(hidden []*attribute.Attribute) ([]byte, []byte, error) {
	secret := secretBlocks(hidden)
	commitment, opening := lazer.AnonUserCommit(secret)
	return commitment, opening, nil
}

// CombineHiddenPublic picks the tier for the issuer attribute count, encodes
// the issuer's attributes (metadata + public) into the tier's issuer blocks,
// and bundles them with the commitment and tier so Sign can add them and
// blind-sign. The result is carried as []uint32 to match the scheme contract.
func CombineHiddenPublic(commitment []byte, publicAttributes []*attribute.Attribute) []uint32 {
	tier := lazer.AnonTierForNpub(len(publicAttributes))
	if tier < 0 {
		// too many attributes; Sign will reject the tier=-1 bundle.
		return bytesToU32(bundle(commitment, nil, -1))
	}
	return bytesToU32(bundle(commitment, pubBlocksForTier(publicAttributes, tier), tier))
}

// Sign blind-signs the commitment after the issuer adds its blocks. The bundled
// (commitment, issuer message, tier) arrives via the []uint32 contract type.
func Sign(pk gabikeys.PublicKey, sk gabikeys.PrivateKey, msg []uint32) (credtypes.Signature, error) {
	pubK, ok := pk.(*PublicKey)
	if !ok {
		return nil, errors.New("lazeranon.Sign: unsupported public key type")
	}
	privK, ok := sk.(*PrivateKey)
	if !ok {
		return nil, errors.New("lazeranon.Sign: unsupported private key type")
	}

	commitment, pubMsg, tier := unbundle(u32ToBytes(msg))
	if tier < 0 {
		return nil, errors.Errorf("lazeranon.Sign: too many issuer attributes (max %d)", lazer.AnonNpubMax)
	}

	signer := lazer.AnonSignerInit(pubK.Pk, privK.Sk)
	defer lazer.AnonSignerClear(&signer)

	rc, blindsig := lazer.AnonSignerSign(&signer, commitment, pubMsg, tier)
	if rc != 1 {
		return nil, errors.New("lazeranon.Sign: masked message rejected (invalid well-formedness proof)")
	}

	return &lazerSignature{Pk: pubK.Pk, Blindsig: blindsig, Tier: tier}, nil
}

// GenerateSalt has no role in lazer (the opening replaces zkDilithium's salt).
func GenerateSalt() ([]byte, error) {
	return []byte{}, nil
}

// --- encoding helpers ---

// secretBlocks derives the nSecret secret blocks (AnonSecretLen bytes) from the
// hidden attributes: a single sha256 over their hashes. The secret is never
// disclosed, so only the committer needs this mapping (it is stored in the
// opening and not recomputed at disclosure).
func secretBlocks(hidden []*attribute.Attribute) []byte {
	h := sha256.New()
	for _, a := range hidden {
		h.Write(a.Hash)
	}
	sum := h.Sum(nil) // 32 bytes = AnonSecretLen
	out := make([]byte, lazer.AnonSecretLen)
	copy(out, sum)
	return out
}

// attrBlock is the 64-bit block bound for an issuer attribute: the first
// blockBytes of its hash. The issuer, the client (at disclosure) and the
// verifier must all agree on this mapping.
func attrBlock(attr *attribute.Attribute) []byte {
	b := make([]byte, blockBytes)
	copy(b, attr.Hash)
	return b
}

// pubBlocksForTier packs the issuer attributes into the tier's issuer message
// (AnonTierNpub(tier) blocks): attribute j -> issuer block j, the rest zero.
func pubBlocksForTier(publicAttributes []*attribute.Attribute, tier int) []byte {
	out := make([]byte, lazer.AnonTierNpub(tier)*blockBytes)
	for j, a := range publicAttributes {
		copy(out[j*blockBytes:(j+1)*blockBytes], attrBlock(a))
	}
	return out
}

// bundle / unbundle pack (commitment, issuer message, tier) into one byte
// string: uint32(len(commitment)), int32(tier), the commitment, then the issuer
// message. tier may be -1 (too many attributes), which Sign rejects.
func bundle(commitment, pubMsg []byte, tier int) []byte {
	out := make([]byte, 8+len(commitment)+len(pubMsg))
	binary.BigEndian.PutUint32(out, uint32(len(commitment)))
	binary.BigEndian.PutUint32(out[4:], uint32(int32(tier)))
	copy(out[8:], commitment)
	copy(out[8+len(commitment):], pubMsg)
	return out
}

func unbundle(b []byte) (commitment, pubMsg []byte, tier int) {
	n := int(binary.BigEndian.Uint32(b))
	tier = int(int32(binary.BigEndian.Uint32(b[4:])))
	commitment = b[8 : 8+n]
	pubMsg = b[8+n:]
	return
}

// bytesToU32 / u32ToBytes losslessly round-trip an opaque byte string through
// the []uint32 contract type. Word 0 holds the byte length; the rest hold the
// bytes big-endian, zero padded.
func bytesToU32(b []byte) []uint32 {
	n := len(b)
	words := (n + 3) / 4
	out := make([]uint32, 1+words)
	out[0] = uint32(n)
	for i := 0; i < words; i++ {
		var w [4]byte
		hi := i*4 + 4
		if hi > n {
			hi = n
		}
		copy(w[:], b[i*4:hi])
		out[1+i] = binary.BigEndian.Uint32(w[:])
	}
	return out
}

func u32ToBytes(u []uint32) []byte {
	if len(u) == 0 {
		return nil
	}
	n := int(u[0])
	buf := make([]byte, (len(u)-1)*4)
	for i := 1; i < len(u); i++ {
		binary.BigEndian.PutUint32(buf[(i-1)*4:], u[i])
	}
	if n > len(buf) {
		n = len(buf)
	}
	return buf[:n]
}
