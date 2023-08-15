package txhelper

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"testing"
	"time"
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
		pksP := make([]*Pubkey, num)
		sigs := make([]Signature, num)

		for i := 0; i < num; i++ {
			sigCtx.generate(&keys[i])
			pks[i] = sigCtx.getPubKey(&keys[i])
			pksP[i] = &pks[i]
			sigs[i] = sigCtx.sign(&keys[i], msg)
			if !sigCtx.verify(&pks[i], msg, sigs[i]) {
				tester.Fatal("invalid individual signature")
			}
		}

		aggregateSig := sigCtx.aggregateSignatures(sigs)
		if !sigCtx.batchVerify(pksP, msg, aggregateSig) {
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

func BenchmarkSignatureContext_BatchVerify(tester *testing.B) {
	sigCtx := NewSigContext(2)
	nums := []int{5, 10, 100}
	for j := range nums {
		msg := make([]byte, 32)
		rand.Read(msg) // some msg, doesn't have to be purely random
		keys := make([]SigKeyPair, nums[j])
		pks := make([]Pubkey, nums[j])
		pksP := make([]*Pubkey, nums[j])
		sigs := make([]Signature, nums[j])

		for i := 0; i < nums[j]; i++ {
			sigCtx.generate(&keys[i])
			pks[i] = sigCtx.getPubKey(&keys[i])
			pksP[i] = &pks[i]
			sigs[i] = sigCtx.sign(&keys[i], msg)
			if !sigCtx.verify(&pks[i], msg, sigs[i]) {
				tester.Fatal("invalid individual signature")
			}
		}

		var sigVerTime time.Duration

		aggregateSig := sigCtx.aggregateSignatures(sigs)
		var s bool
		for i := 0; i < tester.N; i++ {
			start := time.Now()
			s = sigCtx.batchVerify(pksP, msg, aggregateSig) // todo add aggregated
			sigVerTime += time.Since(start)
		}
		result = s
		if !result {
			tester.Fatal("invalid aggregate BLS signature")
		} else {
			fmt.Print("verification time per pk from (", nums[j], "):", sigVerTime/time.Duration(nums[j]*tester.N))
		}
	}
}
