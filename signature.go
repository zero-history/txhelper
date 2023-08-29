/**********************************************************************
 * Copyright (c) 2017 Jayamine Alupotha                               *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

package txhelper

import (
	"bytes"
	"crypto/cipher"
	"errors"
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

type hashablePoint interface {
	Hash([]byte) kyber.Point
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

// NewSigContext assigns ctx objects
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
		sig, err = signBLS(ctx.pairingSuite, kp.Sk, kp.Pk, msg)
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
		err = verifyBLS(ctx.pairingSuite, pk.kyber, msg, sig)
		if err != nil {
			return false
		}

	}
	return true
}

func (ctx *SignatureContext) diffSign(kps []*SigKeyPair, negkps []*SigKeyPair, diffPK *Pubkey, msg []byte) Signature {
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

		sig, err = signBLS(ctx.pairingSuite, aggregateSk, diffPK.kyber, msg)
		if err != nil && ctx.SigType == 2 {
			panic("could not bls-aggregate-sign")
		}
	} else {
		log.Fatal("unknown sigType:", ctx.SigType)
	}

	return sig
}

func (ctx *SignatureContext) getDiffPubKeyFromKeyPairs(keys []*SigKeyPair, negKeys []*SigKeyPair, pk *Pubkey) {
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

func (ctx *SignatureContext) getDiffPubKey(keys []*Pubkey, negKeys []*Pubkey, pk *Pubkey) {
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

func (ctx *SignatureContext) diffPK(kps []*Pubkey, negKeys []*Pubkey) []byte {
	var pk Pubkey
	aggregatePkBytes := new(bytes.Buffer)
	ctx.getDiffPubKey(kps, negKeys, &pk)
	size, _ := pk.kyber.MarshalTo(aggregatePkBytes)
	if size != int(ctx.PkSize) {
		log.Fatal("different pk sizes")
	}
	return aggregatePkBytes.Bytes()
}

func (ctx *SignatureContext) diffPKFromPairs(kps []*SigKeyPair, negKeys []*SigKeyPair) []byte {
	var pk Pubkey
	aggregatePkBytes := new(bytes.Buffer)
	ctx.getDiffPubKeyFromKeyPairs(kps, negKeys, &pk)
	size, _ := pk.kyber.MarshalTo(aggregatePkBytes)
	if size != int(ctx.PkSize) {
		log.Fatal("different pk sizes")
	}
	return aggregatePkBytes.Bytes()
}

// aggregateSignatures This is modified to remove copying signature bytes (AggregateSignatures from dedis/kyber)
func (ctx *SignatureContext) aggregateSignatures(sigs []Signature) Signature {
	sig := ctx.pairingSuite.G1().Point()
	for i := 0; i < len(sigs); i++ {
		sigToAdd := ctx.pairingSuite.G1().Point()
		if err := sigToAdd.UnmarshalBinary(sigs[i]); err != nil {
			return nil
		}
		sig.Add(sig, sigToAdd)
	}
	sigByte, _ := sig.MarshalBinary()
	return sigByte
}

// batchVerify This is modified to remove copying public key bytes (BatchVerify from dedis/kyber)
func (ctx *SignatureContext) batchVerify(publics []Pubkey, msg []byte, sig []byte) bool {
	s := ctx.pairingSuite.G1().Point()
	if err := s.UnmarshalBinary(sig); err != nil {
		return false
	}

	var aggregatedLeft kyber.Point
	for i := range publics {
		hashable, ok := ctx.pairingSuite.G1().Point().(hashablePoint)
		if !ok {
			return false
		}
		pkBytes, _ := publics[i].kyber.MarshalBinary()
		HM := hashable.Hash(append(msg, pkBytes...))
		pair := ctx.pairingSuite.Pair(HM, publics[i].kyber)

		if i == 0 {
			aggregatedLeft = pair
		} else {
			aggregatedLeft.Add(aggregatedLeft, pair)
		}
	}

	right := ctx.pairingSuite.Pair(s, ctx.pairingSuite.G2().Point().Base())
	if !aggregatedLeft.Equal(right) {
		return false
	}
	return true
}

// batchVerify This is modified to remove copying public key bytes (BatchVerify from dedis/kyber)
func (ctx *SignatureContext) batchVerifyMultipleMsg(publics []Pubkey, msgs [][]byte, sig []byte) bool {
	s := ctx.pairingSuite.G1().Point()
	if err := s.UnmarshalBinary(sig); err != nil {
		return false
	}

	var aggregatedLeft kyber.Point
	for i := range publics {
		hashable, ok := ctx.pairingSuite.G1().Point().(hashablePoint)
		if !ok {
			return false
		}
		pkBytes, _ := publics[i].kyber.MarshalBinary()
		HM := hashable.Hash(append(msgs[i], pkBytes...))
		pair := ctx.pairingSuite.Pair(HM, publics[i].kyber)

		if i == 0 {
			aggregatedLeft = pair
		} else {
			aggregatedLeft.Add(aggregatedLeft, pair)
		}
	}

	right := ctx.pairingSuite.Pair(s, ctx.pairingSuite.G2().Point().Base())
	if !aggregatedLeft.Equal(right) {
		return false
	}
	return true
}

func (ctx *SignatureContext) marshelKeys(kp *SigKeyPair, buf *bytes.Buffer) {
	if ctx.SigType == 1 || ctx.SigType == 2 {
		_, _ = kp.Pk.MarshalTo(buf)
		_, _ = kp.Sk.MarshalTo(buf)
	}
}

func (ctx *SignatureContext) unmarshelKeys(kp *SigKeyPair, buf []byte) {
	if ctx.SigType == 1 {
		kp.Pk = ctx.suite.Point().Base()
		kp.Sk = ctx.suite.Scalar()
		_ = kp.Pk.UnmarshalBinary(buf[:ctx.PkSize])
		_ = kp.Sk.UnmarshalBinary(buf[ctx.PkSize:])
	}
	if ctx.SigType == 2 {
		kp.Pk = ctx.pairingSuite.G2().Point().Base()
		kp.Sk = ctx.pairingSuite.G2().Scalar()
		_ = kp.Pk.UnmarshalBinary(buf[:ctx.PkSize])
		_ = kp.Sk.UnmarshalBinary(buf[ctx.PkSize:])
	}
}

func (ctx *SignatureContext) marshelPublicKey(kp *SigKeyPair, buf *bytes.Buffer) {
	if buf.Len() != int(ctx.PkSize) {
		log.Fatal("invalid pk size")
	}
	if ctx.SigType == 1 || ctx.SigType == 2 {
		_, _ = kp.Pk.MarshalTo(buf)
	}
}

func (ctx *SignatureContext) unmarshelPublicKeys(pk *Pubkey, buf *bytes.Buffer) {
	if ctx.SigType == 1 {
		pk.kyber = ctx.suite.Point().Base()
		_, _ = pk.kyber.UnmarshalFrom(buf)
	}
	if ctx.SigType == 2 {
		pk.kyber = ctx.pairingSuite.G2().Point().Base()
		_, _ = pk.kyber.UnmarshalFrom(buf)
	}
}
func (ctx *SignatureContext) unmarshelPublicKeysFromBytes(pk *Pubkey, pkBytes []byte) {
	if ctx.SigType == 1 {
		pk.kyber = ctx.suite.Point().Base()
		_ = pk.kyber.UnmarshalBinary(pkBytes)
	}
	if ctx.SigType == 2 {
		pk.kyber = ctx.pairingSuite.G2().Point().Base()
		_ = pk.kyber.UnmarshalBinary(pkBytes)
	}
}

// BLSSign is an updated version of original dedis/kyber bls signing for pk-based message signing to avoid searching for duplicate msgs
// because we already make sure that public keys are unique
func signBLS(suite pairing.Suite, sk kyber.Scalar, pk kyber.Point, msg []byte) ([]byte, error) {
	hashable, ok := suite.G1().Point().(hashablePoint)
	if !ok {
		return nil, errors.New("point needs to implement hashablePoint")
	}
	pkBytes, _ := pk.MarshalBinary()
	HM := hashable.Hash(append(msg, pkBytes...))
	xHM := HM.Mul(sk, HM)

	s, err := xHM.MarshalBinary()
	if err != nil {
		return nil, err
	}
	return s, nil
}

func verifyBLS(suite pairing.Suite, pk kyber.Point, msg, sig []byte) error {
	hashable, ok := suite.G1().Point().(hashablePoint)
	if !ok {
		return errors.New("bls: point needs to implement hashablePoint")
	}
	var HM kyber.Point
	pkBytes, _ := pk.MarshalBinary()
	HM = hashable.Hash(append(msg, pkBytes...))
	left := suite.Pair(HM, pk)
	s := suite.G1().Point()
	if err := s.UnmarshalBinary(sig); err != nil {
		return err
	}
	right := suite.Pair(s, suite.G2().Point().Base())
	if !left.Equal(right) {
		return errors.New("bls: invalid signature")
	}
	return nil
}
