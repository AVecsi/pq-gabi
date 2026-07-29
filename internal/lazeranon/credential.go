//go:build lazer

package lazeranon

import (
	"bytes"
	"encoding/json"

	"github.com/AVecsi/pq-gabi/attribute"
	"github.com/AVecsi/pq-gabi/credtypes"
	"github.com/go-errors/errors"

	"github.com/AVecsi/lazer"
)

// lazerCredential implements credtypes.Credential.
type lazerCredential struct {
	signature     *lazerSignature
	attrs         []*attribute.Attribute
	attrCount     int
	userAttrCount int
}

// lazerCredentialDisclosure implements credtypes.CredentialDisclosure.
type lazerCredentialDisclosure struct {
	DisclosedAttrs       []*attribute.Attribute   `json:"disclosedAttributes"`
	DisclosedAttrIndices []int                    `json:"disclosedAttributeIndices"`
	NumAllAttributes     int                      `json:"numOfAllAttributes"`
	NumUserAttributes    int                      `json:"numOfUserAttributes"`
	SigProof             credtypes.SignatureProof `json:"signatureProof"`
}

// lazerDisclosureProof implements credtypes.DisclosureProof. Each credential's
// disclosure carries its own self-contained lazer proof (P2); there is no
// separate cross-credential attribute proof.
type lazerDisclosureProof struct {
	CredDisclosures []credtypes.CredentialDisclosure `json:"credentialDisclosures"`
}

// lazerSignatureProof implements credtypes.SignatureProof. It wraps the lazer
// disclosure proof (P2) plus everything the verifier needs to check it: the
// issuer public key, the disclosed block indices, and the public message
// (disclosed blocks set, the rest zero).
type lazerSignatureProof struct {
	Proof   []byte `json:"proof"`
	Pk      []byte `json:"pk"`
	PubMvec []uint `json:"pubMvec"`
	MsgPub  []byte `json:"msgPub"`
	Tier    int    `json:"tier"`
}

// blockIndex maps a gabi attribute index to its message block index. The first
// userAttrCount attributes are the (hidden) secret, occupying blocks
// [0, nSecret); each subsequent attribute occupies one issuer block starting at
// nSecret. Disclosing a hidden/secret attribute is not supported.
func blockIndex(gabiIdx, userAttrCount int) (uint, error) {
	if gabiIdx < userAttrCount {
		return 0, errors.Errorf("lazeranon: cannot disclose hidden attribute %d (the link secret stays hidden)", gabiIdx)
	}
	return uint(nSecret + gabiIdx - userAttrCount), nil
}

// NewCredential constructs a lazer credential. On fresh issuance the client
// supplies the opaque opening (the saved randomness r); on reload it is already
// carried by the deserialized signature, so opening is nil.
func NewCredential(
	sig credtypes.Signature,
	attrs []*attribute.Attribute,
	attrCount int,
	userAttrCount int,
	opening []byte,
) (credtypes.Credential, error) {
	concreteSig, ok := sig.(*lazerSignature)
	if !ok {
		return nil, errors.New("lazeranon.NewCredential: unsupported signature type")
	}
	if attrCount-userAttrCount > lazer.AnonNpubMax {
		return nil, errors.Errorf("lazeranon.NewCredential: %d issuer attributes exceeds the %d-attribute cap", attrCount-userAttrCount, lazer.AnonNpubMax)
	}
	if opening != nil {
		concreteSig.Opening = opening
	}

	return &lazerCredential{
		signature:     concreteSig,
		attrs:         attrs,
		attrCount:     attrCount,
		userAttrCount: userAttrCount,
	}, nil
}

// CreateDisclosureProof bundles the per-credential disclosures (the proofs were
// already produced in CreateDisclosure).
func CreateDisclosureProof(credentials []credtypes.Credential, disclosures []credtypes.CredentialDisclosure) (credtypes.DisclosureProof, error) {
	if len(credentials) != len(disclosures) {
		return nil, errors.New("lazeranon: credentials and disclosures count must match")
	}
	return &lazerDisclosureProof{CredDisclosures: disclosures}, nil
}

// --- credtypes.Credential ---

func (c *lazerCredential) Signature() credtypes.Signature     { return c.signature }
func (c *lazerCredential) Attributes() []*attribute.Attribute { return c.attrs }
func (c *lazerCredential) UserAttrCount() int                 { return c.userAttrCount }

func (c *lazerCredential) UpdateAttributes(keepCount int, attrs []*attribute.Attribute) error {
	c.attrs = append(c.attrs[:keepCount], attrs...)
	c.attrCount = len(c.attrs)
	if c.attrCount-c.userAttrCount > lazer.AnonNpubMax {
		return errors.Errorf("lazeranon.UpdateAttributes: %d issuer attributes exceeds the %d-attribute cap", c.attrCount-c.userAttrCount, lazer.AnonNpubMax)
	}
	return nil
}

// CreateDisclosure produces the lazer disclosure proof for the given attribute
// indices (which must be issuer attributes; the secret cannot be disclosed).
func (c *lazerCredential) CreateDisclosure(disclosedAttributeIndices []int) (credtypes.CredentialDisclosure, error) {
	tier := lazer.AnonTierForNpub(c.attrCount - c.userAttrCount)
	if tier < 0 {
		return nil, errors.Errorf("lazeranon.CreateDisclosure: %d issuer attributes exceeds the %d-attribute cap", c.attrCount-c.userAttrCount, lazer.AnonNpubMax)
	}

	// Reconstruct the issuer blocks the issuer signed, from the public
	// attributes (the client re-derives them, exactly as zkDilithium does).
	pubMsg := pubBlocksForTier(c.attrs[c.userAttrCount:], tier)

	pubMvec := make([]uint, len(disclosedAttributeIndices))
	disclosedAttrs := make([]*attribute.Attribute, len(disclosedAttributeIndices))
	msgPub := make([]byte, nmsgBytes(tier))
	for i, idx := range disclosedAttributeIndices {
		if idx < 0 || idx >= c.attrCount {
			return nil, errors.Errorf("lazeranon.CreateDisclosure: index %d out of range [0,%d)", idx, c.attrCount)
		}
		b, err := blockIndex(idx, c.userAttrCount)
		if err != nil {
			return nil, err
		}
		pubMvec[i] = b
		disclosedAttrs[i] = c.attrs[idx]
		copy(msgPub[b*blockBytes:(b+1)*blockBytes], attrBlock(c.attrs[idx]))
	}

	rc, proof := lazer.AnonUserDisclose(c.signature.Pk, c.signature.Opening, pubMsg, c.signature.Blindsig, pubMvec, tier)
	if rc != 1 {
		return nil, errors.New("lazeranon.CreateDisclosure: disclosure proof generation failed (bad opening/blindsig)")
	}

	return &lazerCredentialDisclosure{
		DisclosedAttrs:       disclosedAttrs,
		DisclosedAttrIndices: disclosedAttributeIndices,
		NumAllAttributes:     c.attrCount,
		NumUserAttributes:    c.userAttrCount,
		SigProof: &lazerSignatureProof{
			Proof:   proof,
			Pk:      c.signature.Pk,
			PubMvec: pubMvec,
			MsgPub:  msgPub,
			Tier:    tier,
		},
	}, nil
}

// --- credtypes.CredentialDisclosure ---

func (d *lazerCredentialDisclosure) DisclosedAttributes() []*attribute.Attribute { return d.DisclosedAttrs }
func (d *lazerCredentialDisclosure) DisclosedAttributeIndices() []int            { return d.DisclosedAttrIndices }
func (d *lazerCredentialDisclosure) NumOfAllAttributes() int                     { return d.NumAllAttributes }
func (d *lazerCredentialDisclosure) NumOfUserAttributes() int                    { return d.NumUserAttributes }
func (d *lazerCredentialDisclosure) SignatureProof() credtypes.SignatureProof    { return d.SigProof }

// --- credtypes.SignatureProof ---

func (p *lazerSignatureProof) Verify() bool {
	verifier := lazer.AnonVerifierInit(p.Pk, p.Tier)
	defer lazer.AnonVerifierClear(&verifier)
	return lazer.AnonVerifierVrfy(&verifier, p.MsgPub, p.PubMvec, p.Proof) == 1
}

func (p *lazerSignatureProof) ProofBytes() []byte     { return p.Proof }
func (p *lazerSignatureProof) SaltedCredHash() []byte { return nil } // unused by lazer
func (p *lazerSignatureProof) Salt() []byte           { return nil } // unused by lazer

// --- credtypes.DisclosureProof ---

// Verify checks every credential disclosure: it rebuilds the expected public
// message from the claimed disclosed attribute values at their block positions
// (binding the human-meaningful values to the cryptographic proof), checks it
// matches the proof's public message, then verifies the lazer proof.
func (p *lazerDisclosureProof) Verify() bool {
	for _, cd := range p.CredDisclosures {
		sp, ok := cd.SignatureProof().(*lazerSignatureProof)
		if !ok {
			return false
		}

		indices := cd.DisclosedAttributeIndices()
		attrs := cd.DisclosedAttributes()
		if len(indices) != len(attrs) {
			return false
		}
		nmsg := nSecret + lazer.AnonTierNpub(sp.Tier)
		expected := make([]byte, nmsg*blockBytes)
		for i, idx := range indices {
			b, err := blockIndex(idx, cd.NumOfUserAttributes())
			if err != nil || int(b) >= nmsg {
				return false
			}
			copy(expected[b*blockBytes:(b+1)*blockBytes], attrBlock(attrs[i]))
		}
		if !bytes.Equal(expected, sp.MsgPub) {
			return false
		}
		if !sp.Verify() {
			return false
		}
	}
	return true
}

// AttrProof returns nil: lazer has no separate cross-credential attribute proof.
func (p *lazerDisclosureProof) AttrProof() []byte { return nil }

func (p *lazerDisclosureProof) CredentialDisclosures() []credtypes.CredentialDisclosure {
	return p.CredDisclosures
}

func ParseDisclosureProof(data []byte) (credtypes.DisclosureProof, error) {
	var proof lazerDisclosureProof
	if err := json.Unmarshal(data, &proof); err != nil {
		return nil, err
	}
	return &proof, nil
}

// --- JSON (un)marshalling for the interface-typed fields ---

func (p *lazerDisclosureProof) UnmarshalJSON(data []byte) error {
	var raw struct {
		CredentialDisclosures []json.RawMessage `json:"credentialDisclosures"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	for _, rawDisc := range raw.CredentialDisclosures {
		var disc lazerCredentialDisclosure
		if err := json.Unmarshal(rawDisc, &disc); err != nil {
			return err
		}
		p.CredDisclosures = append(p.CredDisclosures, &disc)
	}
	return nil
}

func (d *lazerCredentialDisclosure) UnmarshalJSON(data []byte) error {
	var raw struct {
		DisclosedAttributes       []*attribute.Attribute `json:"disclosedAttributes"`
		DisclosedAttributeIndices []int                  `json:"disclosedAttributeIndices"`
		NumOfAllAttributes        int                    `json:"numOfAllAttributes"`
		NumOfUserAttributes       int                    `json:"numOfUserAttributes"`
		SignatureProof            json.RawMessage        `json:"signatureProof"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	d.DisclosedAttrs = raw.DisclosedAttributes
	d.DisclosedAttrIndices = raw.DisclosedAttributeIndices
	d.NumAllAttributes = raw.NumOfAllAttributes
	d.NumUserAttributes = raw.NumOfUserAttributes

	if len(raw.SignatureProof) > 0 && string(raw.SignatureProof) != "null" {
		var sp lazerSignatureProof
		if err := json.Unmarshal(raw.SignatureProof, &sp); err != nil {
			return err
		}
		d.SigProof = &sp
	}
	return nil
}
