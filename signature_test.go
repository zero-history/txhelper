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

func TestDiffSig(tester *testing.T) {
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
			pk1Bytes := sigCtx.diffPK(pks1, negpks1)
			sigCtx.unmarshelPublicKeysFromBytes(&pk2, pk1Bytes)

			sig := sigCtx.diffSign(keys1, negkeys1, &pk2, msg)
			if !sigCtx.verify(&pk2, msg, sig) {
				tester.Errorf("invalid diff signature")
			}

			pk1Bytes = sigCtx.diffPK(pks1, negpks1)
			sigCtx.unmarshelPublicKeysFromBytes(&pk2, pk1Bytes)
			if !sigCtx.verify(&pk2, msg, sig) {
				tester.Errorf("invalid difference pks1")
			}

			pk2Bytes := sigCtx.diffPKFromPairs(keys1, negkeys1)
			sigCtx.unmarshelPublicKeysFromBytes(&pk3, pk2Bytes)
			if !sigCtx.verify(&pk3, msg, sig) {
				tester.Errorf("invalid difference keys1")
			}

			pk2Bytes = sigCtx.diffPKFromPairs(keys2, negkeys2)
			sigCtx.unmarshelPublicKeysFromBytes(&pk3, pk2Bytes)
			if !sigCtx.verify(&pk3, msg, sig) {
				tester.Errorf("invalid difference keys2")
			}
		}
	}
}

func TestAggregateBLSSig(tester *testing.T) {
	sigCtx := NewSigContext(2)
	for j := 0; j < 10; j++ {
		msg := make([]byte, 32)
		rand.Read(msg) // some msg, doesn't have to be purely random
		num := 5
		keys := make([]SigKeyPair, num)
		pks := make([]Pubkey, num)
		sigs := make([]Signature, num)

		for i := 0; i < num; i++ {
			sigCtx.generate(&keys[i])
			pks[i] = sigCtx.getPubKey(&keys[i])
			sigs[i] = sigCtx.sign(&keys[i], msg)
			if !sigCtx.verify(&pks[i], msg, sigs[i]) {
				tester.Fatal("invalid individual signature")
			}
		}

		aggregateSig := sigCtx.aggregateSignatures(sigs)
		if !sigCtx.batchVerify(pks, msg, aggregateSig) {
			tester.Fatal("invalid aggregate BLS signature")
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

func BenchmarkSignatureContext_BatchVerify5(tester *testing.B) {
	sigCtx := NewSigContext(2)
	num := 5
	msg := make([]byte, 32)
	rand.Read(msg) // some msg, doesn't have to be purely random
	keys := make([]SigKeyPair, num)
	pks := make([]Pubkey, num)
	sigs := make([]Signature, num)

	for i := 0; i < num; i++ {
		sigCtx.generate(&keys[i])
		pks[i] = sigCtx.getPubKey(&keys[i])
		sigs[i] = sigCtx.sign(&keys[i], msg)
		if !sigCtx.verify(&pks[i], msg, sigs[i]) {
			tester.Fatal("invalid individual signature")
		}
	}

	aggregateSig := sigCtx.aggregateSignatures(sigs)
	var s bool
	for i := 0; i < tester.N; i++ {
		s = sigCtx.batchVerify(pks, msg, aggregateSig) // todo add aggregated
	}
	if !s {
		tester.Fatal("invalid aggregate BLS signature")
	}
	result = s
}

func BenchmarkSignatureContext_BatchVerify50(tester *testing.B) {
	sigCtx := NewSigContext(2)
	num := 50
	msg := make([]byte, 32)
	rand.Read(msg) // some msg, doesn't have to be purely random
	keys := make([]SigKeyPair, num)
	pks := make([]Pubkey, num)
	sigs := make([]Signature, num)

	for i := 0; i < num; i++ {
		sigCtx.generate(&keys[i])
		pks[i] = sigCtx.getPubKey(&keys[i])
		sigs[i] = sigCtx.sign(&keys[i], msg)
		if !sigCtx.verify(&pks[i], msg, sigs[i]) {
			tester.Fatal("invalid individual signature")
		}
	}

	aggregateSig := sigCtx.aggregateSignatures(sigs)
	var s bool
	for i := 0; i < tester.N; i++ {
		s = sigCtx.batchVerify(pks, msg, aggregateSig)
	}
	if !s {
		tester.Fatal("invalid aggregate BLS signature")
	}
	result = s
}

func BenchmarkSignatureContext_BatchVerify500(tester *testing.B) {
	sigCtx := NewSigContext(2)
	num := 500
	msg := make([]byte, 32)
	rand.Read(msg) // some msg, doesn't have to be purely random
	keys := make([]SigKeyPair, num)
	pks := make([]Pubkey, num)
	sigs := make([]Signature, num)

	for i := 0; i < num; i++ {
		sigCtx.generate(&keys[i])
		pks[i] = sigCtx.getPubKey(&keys[i])
		sigs[i] = sigCtx.sign(&keys[i], msg)
		if !sigCtx.verify(&pks[i], msg, sigs[i]) {
			tester.Fatal("invalid individual signature")
		}
	}

	aggregateSig := sigCtx.aggregateSignatures(sigs)
	var s bool
	for i := 0; i < tester.N; i++ {
		s = sigCtx.batchVerify(pks, msg, aggregateSig)
	}
	if !s {
		tester.Fatal("invalid aggregate BLS signature")
	}
	result = s
}
