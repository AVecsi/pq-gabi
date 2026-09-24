//go:build lazer

package lazeranon

import (
	"bytes"
	"crypto/subtle"
	"encoding/json"

	"github.com/AVecsi/pq-gabi/attribute"
	"github.com/AVecsi/pq-gabi/credtypes"
	"github.com/AVecsi/pq-gabi/gabikeys"
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
	// NonceBytes is the verifier's per-session challenge this proof was made
	// for. Carried so Verify can reject a proof presented to a different
	// session.
	//
	// SECURITY — NOT YET COMPLETE for this backend. AnonUserDisclose takes no
	// nonce, and the LNP transcript is seeded by the ppseed lin_prover_init is
	// given, which anoncred.c derives from a fixed domain byte. So the nonce is
	// only carried and compared here: an attacker who edits this field has the
	// proof accepted. zkDilithium binds it properly; lazer does not yet.
	NonceBytes []byte `json:"nonce"`
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
// already produced in CreateDisclosure) and binds them to the verifier's
// session nonce.
//
// Note for whoever completes the cryptographic binding: unlike zkDilithium,
// lazer produces its proof in Credential.CreateDisclosure, one per credential,
// and this function only bundles them. So the nonce has to reach
// CreateDisclosure (whose signature is fixed by credtypes.Credential) rather
// than this function. Binding it here is not possible.
func CreateDisclosureProof(credentials []credtypes.Credential, disclosures []credtypes.CredentialDisclosure, nonce []byte) (credtypes.DisclosureProof, error) {
	if len(credentials) != len(disclosures) {
		return nil, errors.New("lazeranon: credentials and disclosures count must match")
	}
	// Refused rather than defaulted: a zero-length nonce is the same challenge
	// in every session, so it binds nothing while producing a proof that looks
	// bound to anything inspecting it.
	if len(nonce) == 0 {
		return nil, errors.New("lazeranon.CreateDisclosureProof: empty session nonce")
	}
	return &lazerDisclosureProof{CredDisclosures: disclosures, NonceBytes: nonce}, nil
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
func (c *lazerCredential) CreateDisclosure(disclosedAttributeIndices []int, nonce []byte) (credtypes.CredentialDisclosure, error) {
	if len(nonce) == 0 {
		return nil, errors.New("lazeranon.CreateDisclosure: empty session nonce")
	}
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

func (d *lazerCredentialDisclosure) DisclosedAttributes() []*attribute.Attribute {
	return d.DisclosedAttrs
}
func (d *lazerCredentialDisclosure) DisclosedAttributeIndices() []int         { return d.DisclosedAttrIndices }
func (d *lazerCredentialDisclosure) NumOfAllAttributes() int                  { return d.NumAllAttributes }
func (d *lazerCredentialDisclosure) NumOfUserAttributes() int                 { return d.NumUserAttributes }
func (d *lazerCredentialDisclosure) SignatureProof() credtypes.SignatureProof { return d.SigProof }

// --- credtypes.SignatureProof ---

// Verify checks the proof against the issuer public key the verifier trusts.
//
// The proof carries a copy of the issuer key because lazer's verifier needs the
// Falcon-512 blob, but that copy is chosen by the prover and so proves nothing
// on its own. The trusted key passed in here is what decides: if the proof's
// own key does not match it, the credential was issued by somebody else and
// this is a verification failure.
func (p *lazerSignatureProof) Verify(pk gabikeys.PublicKey, nonce []byte) bool {
	pubK, ok := pk.(*PublicKey)
	if !ok {
		return false
	}
	if !bytes.Equal(pubK.Pk, p.Pk) {
		return false
	}
	verifier := lazer.AnonVerifierInit(pubK.Pk, p.Tier)
	defer lazer.AnonVerifierClear(&verifier)
	return lazer.AnonVerifierVrfy(&verifier, p.MsgPub, p.PubMvec, p.Proof) == 1
}

func (p *lazerSignatureProof) ProofBytes() []byte     { return p.Proof }
func (p *lazerSignatureProof) SaltedCredHash() []byte { return nil } // unused by lazer
func (p *lazerSignatureProof) Salt() []byte           { return nil } // unused by lazer

// --- credtypes.DisclosureProof ---

// Verify checks that the proof was made for this session, then checks every
// credential disclosure: it rebuilds the expected public message from the
// claimed disclosed attribute values at their block positions (binding the
// human-meaningful values to the cryptographic proof), checks it matches the
// proof's public message, then verifies the lazer proof against publicKeys[i],
// the issuer key the verifier trusts for that credential.
func (p *lazerDisclosureProof) Verify(publicKeys []gabikeys.PublicKey, nonce []byte) bool {
	// Before any cryptography: this proof must have been made for the session
	// being verified. Constant-time, and an empty expected nonce always fails,
	// so a caller that forgot to thread one through cannot accidentally accept
	// a proof made for some other session.
	if len(nonce) == 0 {
		return false
	}
	if subtle.ConstantTimeCompare(p.NonceBytes, nonce) != 1 {
		return false
	}

	if len(publicKeys) != len(p.CredDisclosures) {
		return false
	}
	for i, cd := range p.CredDisclosures {
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
		// j, not i: i is the credential index, used below to pick the issuer key.
		for j, idx := range indices {
			b, err := blockIndex(idx, cd.NumOfUserAttributes())
			if err != nil || int(b) >= nmsg {
				return false
			}
			copy(expected[b*blockBytes:(b+1)*blockBytes], attrBlock(attrs[j]))
		}
		if !bytes.Equal(expected, sp.MsgPub) {
			return false
		}
		if !sp.Verify(publicKeys[i], nonce) {
			return false
		}
	}
	return true
}

// AttrProof returns nil: lazer has no separate cross-credential attribute proof.
func (p *lazerDisclosureProof) AttrProof() []byte { return nil }

func (p *lazerDisclosureProof) Nonce() []byte { return p.NonceBytes }

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
		Nonce                 []byte            `json:"nonce"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	p.NonceBytes = raw.Nonce
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
