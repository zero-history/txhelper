package txhelper

import (
	"bytes"
	"crypto/rand"
	"testing"
)

func TestSig(tester *testing.T) {
	for i := int32(1); i < 3; i++ {
		sigCtx := NewSigContext(i)
		for j := 0; j < 10; j++ {
			msg := make([]byte, 32)
			rand.Read(msg)
			var keys SigKeyPair
			var keys1 SigKeyPair
			var kp1 bytes.Buffer
			var kp2 bytes.Buffer
			sigCtx.generate(&keys)
			sigCtx.generate(&keys1)
			sig := sigCtx.sign(&keys, msg)
			pk := sigCtx.getPubKey(&keys)
			if len(sig) != int(sigCtx.SigSize) {
				tester.Errorf("invalid sig size: mentioned %q, wanted %q", keys.Sk.MarshalSize(), sigCtx.SigSize)
			}

			sigCtx.marshelKeys(&keys, &kp1)
			sigCtx.unmarshelKeys(&keys1, &kp1)
			sigCtx.marshelKeys(&keys1, &kp2)

			if !keys1.Pk.Equal(keys.Pk) {
				tester.Errorf("invalid pk")
			}

			if !keys1.Pk.Equal(pk.kyber) {
				tester.Errorf("invalid pk")
			}

			if !sigCtx.verify(&pk, msg, sig) {
				tester.Errorf("invalid signature")
			}
		}
	}
}

func TestAggregateSig(tester *testing.T) {
	for i := int32(1); i < 3; i++ {
		sigCtx := NewSigContext(i)
		for j := 0; j < 10; j++ {
			msg := make([]byte, 32)
			rand.Read(msg) // some msg, doesn't have to be purely random
			num := 5
			keys := make([]SigKeyPair, num)
			negkeys := make([]SigKeyPair, num)
			keys1 := make([]*SigKeyPair, num)
			negkeys1 := make([]*SigKeyPair, num)
			keys2 := make([]*SigKeyPair, num)
			negkeys2 := make([]*SigKeyPair, num)
			pks := make([]Pubkey, num)
			negpks := make([]Pubkey, num)
			pks1 := make([]*Pubkey, num)
			negpks1 := make([]*Pubkey, num)
			var pk2 Pubkey
			var pk3 Pubkey

			for i := 0; i < num; i++ {
				sigCtx.generate(&keys[i])
				sigCtx.generate(&negkeys[i])
				pks[i] = sigCtx.getPubKey(&keys[i])
				negpks[i] = sigCtx.getPubKey(&negkeys[i])
				keys1[i] = &keys[i]
				negkeys1[i] = &negkeys[i]
				keys2[i] = &keys[i]
				negkeys2[i] = &negkeys[i]
				negkeys2[i].Sk = negkeys[i].Sk.Clone()
				negkeys2[i].Pk = negkeys[i].Pk.Clone()
				pks1[i] = &pks[i]
				negpks1[i] = &negpks[i]
			}
			sig := sigCtx.aggregateSign(keys1, negkeys1, msg)

			pk1Bytes := sigCtx.aggregatePK(pks1, negpks1)
			sigCtx.unmarshelPublicKeysFromBytes(&pk2, pk1Bytes)
			if !sigCtx.verify(&pk2, msg, sig) {
				tester.Errorf("invalid aggregation")
			}

			pk1Bytes = sigCtx.aggregatePK(pks1, negpks1)
			sigCtx.unmarshelPublicKeysFromBytes(&pk2, pk1Bytes)
			if !sigCtx.verify(&pk2, msg, sig) {
				tester.Errorf("invalid aggregation")
			}

			pk2Bytes := sigCtx.aggregatePKFromPairs(keys1, negkeys1)
			sigCtx.unmarshelPublicKeysFromBytes(&pk3, pk2Bytes)
			if !sigCtx.verify(&pk3, msg, sig) {
				tester.Errorf("invalid aggregation")
			}

			pk2Bytes = sigCtx.aggregatePKFromPairs(keys2, negkeys2)
			sigCtx.unmarshelPublicKeysFromBytes(&pk3, pk2Bytes)
			if !sigCtx.verify(&pk3, msg, sig) {
				tester.Errorf("invalid aggregation")
			}

			pk2Bytes = sigCtx.aggregatePKFromPairs(keys2, negkeys2)
			sigCtx.unmarshelPublicKeysFromBytes(&pk3, pk2Bytes)
			if !sigCtx.verify(&pk3, msg, sig) {
				tester.Errorf("invalid aggregation")
			}
		}
	}
}

var result bool

func BenchmarkSignatureContext_VerifySchnor(b *testing.B) {
	sigCtx := NewSigContext(1)
	msg := make([]byte, 32)
	rand.Read(msg)
	var keys SigKeyPair
	sigCtx.generate(&keys)
	sig := sigCtx.sign(&keys, msg)
	pk := sigCtx.getPubKey(&keys)
	var s bool
	for i := 0; i < b.N; i++ {
		s = sigCtx.verify(&pk, msg, sig)
	}
	result = s
}

func BenchmarkSignatureContext_VerifyBLS(b *testing.B) {
	sigCtx := NewSigContext(2)
	msg := make([]byte, 32)
	rand.Read(msg)
	var keys SigKeyPair
	sigCtx.generate(&keys)
	sig := sigCtx.sign(&keys, msg)
	pk := sigCtx.getPubKey(&keys)
	var s bool
	for i := 0; i < b.N; i++ {
		s = sigCtx.verify(&pk, msg, sig)
	}
	result = s
}
