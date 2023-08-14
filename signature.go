package txhelper

import (
	"bytes"
	"crypto/cipher"
	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/group/edwards25519"
	"go.dedis.ch/kyber/v3/pairing"
	"go.dedis.ch/kyber/v3/pairing/bn256"
	"go.dedis.ch/kyber/v3/sign/bdn"
	"go.dedis.ch/kyber/v3/sign/schnorr"
	"go.dedis.ch/kyber/v3/util/key"
	"go.dedis.ch/kyber/v3/util/random"
	"log"
)

type Suite interface {
	kyber.Group
	kyber.Random
}

type Signature []byte

type Generator interface {
	NewKey(random cipher.Stream) kyber.Scalar
}

type Pubkey struct {
	kyber kyber.Point
}

type SigKeyPair struct {
	Pk kyber.Point  `json:"p"`
	Sk kyber.Scalar `json:"s"`
}

type SignatureContext struct {
	SigType      int32         // signature module
	suite        key.Suite     // signature suite, e.g., curve
	pairingSuite pairing.Suite // signature suite, e.g., curve
	rand         kyber.Random
	SkSize       int32
	PkSize       int32
	SigSize      int32
}

// New assign ctx objects
// 1 - Schnorr
// 2 - BLS
func NewSigContext(sigType int32) *SignatureContext {
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	if sigType != 1 && sigType != 2 {
		log.Fatal("unknown sig type")
	}
	ctx := SignatureContext{
		SigType: sigType,
	}
	if ctx.SigType == 1 { // Schnorr signature
		ctx.suite = edwards25519.NewBlakeSHA256Ed25519()
		ctx.SkSize = 32
		ctx.PkSize = 32
		ctx.SigSize = 64

	}
	if ctx.SigType == 2 { // Schnorr signature
		ctx.suite = edwards25519.NewBlakeSHA256Ed25519()
		ctx.pairingSuite = pairing.NewSuiteBn256()
		ctx.SkSize = 32
		ctx.PkSize = 128
		ctx.SigSize = 64
	}
	return &ctx
}

func (ctx *SignatureContext) generate(keys *SigKeyPair) {
	var k *key.Pair
	if ctx.SigType == 1 {
		k = key.NewKeyPair(ctx.suite)
		keys.Sk = k.Private
		keys.Pk = k.Public
	} else if ctx.SigType == 2 {
		suite := bn256.NewSuite()
		keys.Sk, keys.Pk = bdn.NewKeyPair(suite, random.New())
	}
}

func (ctx *SignatureContext) getPubKey(keys *SigKeyPair) Pubkey {
	var pk Pubkey
	if ctx.SigType == 1 || ctx.SigType == 2 { // Schnorr signature
		pk.kyber = keys.Pk
	}
	return pk
}

func (ctx *SignatureContext) sign(kp *SigKeyPair, msg []byte) Signature {
	var err error
	var sig Signature

	if ctx.SigType == 1 { // Schnorr signature
		sig, err = schnorr.Sign(ctx.suite, kp.Sk, msg)
		if err != nil {
			panic("could not schnorr-sign")
		}
	} else if ctx.SigType == 2 {
		sig, err = bdn.Sign(ctx.pairingSuite, kp.Sk, msg)
		if err != nil && ctx.SigType == 2 {
			panic("could not bls-sign")
		}
	}
	return sig
}

func (ctx *SignatureContext) verify(pk *Pubkey, msg []byte, sig Signature) bool {
	var err error

	if len(sig) != int(ctx.SigSize) {
		log.Print("invalid signature size")
		return false
	}

	if ctx.SigType == 1 { // Schnorr and bls signatures
		err = schnorr.Verify(ctx.suite, pk.kyber, msg, sig)
		if err != nil {
			return false
		}
	} else if ctx.SigType == 2 { // Schnorr and bls signatures
		err = bdn.Verify(ctx.pairingSuite, pk.kyber, msg, sig)
		if err != nil {
			return false
		}
	}
	return true
}

func (ctx *SignatureContext) aggregateSign(kps []*SigKeyPair, negkps []*SigKeyPair, msg []byte) Signature {
	var err error
	var sig Signature

	if ctx.SigType == 1 { // Schnorr and bls signature
		var aggregateSk kyber.Scalar
		aggregateSk = kps[0].Sk.Clone()
		for i := 1; i < len(kps); i++ {
			aggregateSk = aggregateSk.Add(aggregateSk, kps[i].Sk)
		}
		if negkps != nil && len(negkps) >= 1 {
			for i := 1; i < len(negkps); i++ {
				aggregateSk = aggregateSk.Sub(aggregateSk, negkps[i].Sk)
			}
		}

		sig, err = schnorr.Sign(ctx.suite, aggregateSk, msg)
		if err != nil && ctx.SigType == 1 {
			panic("could not schnorr-aggregate-sign")
		}
	} else if ctx.SigType == 2 { // Schnorr and bls signatures
		var aggregateSk kyber.Scalar
		aggregateSk = kps[0].Sk.Clone()
		for i := 1; i < len(kps); i++ {
			aggregateSk = aggregateSk.Add(aggregateSk, kps[i].Sk)
		}
		if negkps != nil && len(negkps) >= 1 {
			for i := 1; i < len(negkps); i++ {
				aggregateSk = aggregateSk.Sub(aggregateSk, negkps[i].Sk)
			}
		}

		sig, err = bdn.Sign(ctx.pairingSuite, aggregateSk, msg)
		if err != nil && ctx.SigType == 2 {
			panic("could not bls-aggregate-sign")
		}
	} else {
		log.Fatal("unknown sigType:", ctx.SigType)
	}

	return sig
}

func (ctx *SignatureContext) getAggregatePubKeyFromKeyPairs(keys []*SigKeyPair, negKeys []*SigKeyPair, pk *Pubkey) {
	var aggregatePk kyber.Point
	if ctx.SigType == 1 {
		aggregatePk = keys[0].Pk.Clone()
		for i := 1; i < len(keys); i++ {
			aggregatePk.Add(aggregatePk, keys[i].Pk)
		}
		if negKeys != nil && len(negKeys) >= 1 {
			for i := 1; i < len(negKeys); i++ {
				aggregatePk.Sub(aggregatePk, negKeys[i].Pk)
			}
		}
	} else if ctx.SigType == 2 {
		aggregatePk = keys[0].Pk.Clone()
		for i := 1; i < len(keys); i++ {
			aggregatePk.Add(aggregatePk, keys[i].Pk)
		}
		if negKeys != nil && len(negKeys) >= 1 {
			for i := 1; i < len(negKeys); i++ {
				aggregatePk.Sub(aggregatePk, negKeys[i].Pk)
			}
		}
	}
	pk.kyber = aggregatePk.Clone()
}

func (ctx *SignatureContext) getAggregatePubKey(keys []*Pubkey, negKeys []*Pubkey, pk *Pubkey) {
	var aggregatePk kyber.Point
	if ctx.SigType == 1 {
		aggregatePk = keys[0].kyber.Clone()
		for i := 1; i < len(keys); i++ {
			aggregatePk.Add(aggregatePk, keys[i].kyber)
		}
		if negKeys != nil && len(negKeys) >= 1 {
			for i := 1; i < len(negKeys); i++ {
				aggregatePk.Sub(aggregatePk, negKeys[i].kyber)
			}
		}
	} else if ctx.SigType == 2 {
		aggregatePk = keys[0].kyber.Clone()
		for i := 1; i < len(keys); i++ {
			aggregatePk.Add(aggregatePk, keys[i].kyber)
		}
		if negKeys != nil && len(negKeys) >= 1 {
			for i := 1; i < len(negKeys); i++ {
				aggregatePk.Sub(aggregatePk, negKeys[i].kyber)
			}
		}
	}
	pk.kyber = aggregatePk.Clone()
}

func (ctx *SignatureContext) aggregatePK(kps []*Pubkey, negKeys []*Pubkey) []byte {
	var pk Pubkey
	aggregatePkBytes := new(bytes.Buffer)
	ctx.getAggregatePubKey(kps, negKeys, &pk)
	size, _ := pk.kyber.MarshalTo(aggregatePkBytes)
	if size != int(ctx.PkSize) {
		log.Fatal("different pk sizes")
	}
	return aggregatePkBytes.Bytes()
}

func (ctx *SignatureContext) aggregatePKFromPairs(kps []*SigKeyPair, negKeys []*SigKeyPair) []byte {
	var pk Pubkey
	aggregatePkBytes := new(bytes.Buffer)
	ctx.getAggregatePubKeyFromKeyPairs(kps, negKeys, &pk)
	size, _ := pk.kyber.MarshalTo(aggregatePkBytes)
	if size != int(ctx.PkSize) {
		log.Fatal("different pk sizes")
	}
	return aggregatePkBytes.Bytes()
}

func (ctx *SignatureContext) marshelKeys(kp *SigKeyPair, buf *bytes.Buffer) {
	if ctx.SigType == 1 || ctx.SigType == 2 { // Schnorr signature
		_, _ = kp.Pk.MarshalTo(buf)
		_, _ = kp.Sk.MarshalTo(buf)
	}
}

func (ctx *SignatureContext) unmarshelKeys(kp *SigKeyPair, buf *bytes.Buffer) {
	if ctx.SigType == 1 || ctx.SigType == 2 { // Schnorr signature
		_, _ = kp.Pk.UnmarshalFrom(buf)
		_, _ = kp.Sk.UnmarshalFrom(buf)
	}
}

func (ctx *SignatureContext) marshelPublicKey(kp *SigKeyPair, buf *bytes.Buffer) {
	if buf.Len() != int(ctx.PkSize) {
		log.Fatal("invalid pk size")
	}
	if ctx.SigType == 1 || ctx.SigType == 2 { // Schnorr signature
		_, _ = kp.Pk.MarshalTo(buf)
	}
}

func (ctx *SignatureContext) unmarshelPublicKeys(pk *Pubkey, buf *bytes.Buffer) {
	if ctx.SigType == 1 || ctx.SigType == 2 { // Schnorr signature
		var keys SigKeyPair
		ctx.generate(&keys) // for initiating
		pk.kyber = keys.Pk.Base()
		_, _ = pk.kyber.UnmarshalFrom(buf)
	}
}
func (ctx *SignatureContext) unmarshelPublicKeysFromBytes(pk *Pubkey, pkBytes []byte) {
	buf := new(bytes.Buffer)
	buf.Write(pkBytes)
	if ctx.SigType == 1 || ctx.SigType == 2 { // Schnorr signature
		var keys SigKeyPair
		ctx.generate(&keys) // for initiating
		pk.kyber = keys.Pk.Base()
		_, _ = pk.kyber.UnmarshalFrom(buf)
	}
}
