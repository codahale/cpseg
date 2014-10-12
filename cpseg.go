// Package cpseg provides an implementation of the CPS-EG public key encryption
// system, an IND-CCA2 variant of ElGamal described by Seurin and Treger:
//
//     In this paper, we propose a very simple modification to Schnorr-Signed
//     ElGamal encryption such that the resulting scheme is semantically secure
//     under adaptive chosen-ciphertext attacks (IND-CCA2- secure) in the ROM
//     under the Decisional Diffie-Hellman assumption. In fact, we even prove
//     that our new scheme is plaintext-aware in the ROM as defined by Bellare
//     et al. (CRYPTO ’98).
//
// (https://eprint.iacr.org/2012/649.pdf)
package cpseg

import (
	"crypto/rand"
	"crypto/subtle"
	"errors"
	"hash"
	"io"
	"math/big"
)

// ErrDecrypt is returned by Decrypt when the message cannot be decrypted.
var ErrDecrypt = errors.New("message authentication failed")

// Parameters represents the domain parameters for a key. These parameters can
// be shared across many keys.
type Parameters struct {
	P, G *big.Int
	Hash func() hash.Hash
}

// PublicKey represents a CPS-EG public key.
type PublicKey struct {
	Parameters
	H *big.Int
}

// PrivateKey represents a CPS-EG private key.
type PrivateKey struct {
	PublicKey
	X *big.Int
}

// GenerateKey generates a public & private key pair. The Parameters of the
// PrivateKey must already be valid.
func GenerateKey(priv *PrivateKey, rng io.Reader) (err error) {
	priv.X, err = rand.Int(rng, priv.P)
	if err != nil {
		return
	}
	priv.H = new(big.Int).Exp(priv.G, priv.X, priv.P)
	return
}

// Encrypt encrypts the given message with the given public key.
func Encrypt(rng io.Reader, pub *PublicKey, msg []byte) (Y, R, A, s *big.Int, err error) {
	pLen := (pub.P.BitLen() + 7) / 8
	if len(msg) > pLen-11 {
		err = errors.New("message too long")
		return
	}

	// EM = 0x02 || PS || 0x00 || M
	em := make([]byte, pLen-1)
	em[0] = 2
	ps, mm := em[1:len(em)-len(msg)-1], em[len(em)-len(msg):]
	err = nonZeroRandomBytes(ps, rng)
	if err != nil {
		return
	}
	em[len(em)-len(msg)-1] = 0
	copy(mm, msg)

	M := new(big.Int).SetBytes(em)

	// r ← $ℤp*
	r, err := rand.Int(rng, pub.P)
	if err != nil {
		return
	}

	// a ← $ℤp*
	a, err := rand.Int(rng, pub.P)
	if err != nil {
		return
	}

	// R = G^r
	R = new(big.Int).Exp(pub.G, r, pub.P)

	// R′ = X^r
	Rprime := new(big.Int).Exp(pub.H, r, pub.P)

	// Y = MR′
	Y = new(big.Int).Mul(M, Rprime)

	// A = G^a
	A = new(big.Int).Exp(pub.G, a, pub.P)

	// A′ = X^a
	Aprime := new(big.Int).Exp(pub.H, a, pub.P)

	// c = h(Y, R, R′, A, A′)
	c := hc(pub.Hash, Y, R, Rprime, A, Aprime)

	// s = a + cr
	s = new(big.Int).Mul(c, r) // NOT ACTUALLY MOD P DESPITE WHAT THE PAPER SAYS
	s.Add(s, a)

	return
}

// Decrypt decrypts the given message with the given private key. If the message
// is not decryptable (i.e., it's been modified or isn't a valid ciphertext), it
// returns nil.
func Decrypt(priv *PrivateKey, Y, R, A, s *big.Int) ([]byte, error) {
	// R′ = R^x
	Rprime := new(big.Int).Exp(R, priv.X, priv.P)

	// A′ = A^x
	Aprime := new(big.Int).Exp(A, priv.X, priv.P)

	// c = H(Y, R, R′, A, A′)
	c := hc(priv.Hash, Y, R, Rprime, A, Aprime)

	// G^s
	gs := new(big.Int).Exp(priv.G, s, priv.P)

	// X^s
	Xs := new(big.Int).Exp(priv.H, s, priv.P)

	// AR^c
	ARc := new(big.Int).Exp(R, c, priv.P)
	ARc.Mul(ARc, A)
	ARc.Mod(ARc, priv.P)

	// A′R′^c
	ARcprime := new(big.Int).Exp(Rprime, c, priv.P)
	ARcprime.Mul(ARcprime, Aprime)
	ARcprime.Mod(ARcprime, priv.P)

	if gs.Cmp(ARc) != 0 || Xs.Cmp(ARcprime) != 0 {
		return nil, ErrDecrypt
	}

	em := new(big.Int).Div(Y, Rprime).Bytes()
	firstByteIsTwo := subtle.ConstantTimeByteEq(em[0], 2)

	// The remainder of the plaintext must be a string of non-zero random
	// octets, followed by a 0, followed by the message.
	//   lookingForIndex: 1 iff we are still looking for the zero.
	//   index: the offset of the first zero byte.
	var lookingForIndex, index int
	lookingForIndex = 1

	for i := 1; i < len(em); i++ {
		equals0 := subtle.ConstantTimeByteEq(em[i], 0)
		index = subtle.ConstantTimeSelect(lookingForIndex&equals0, i, index)
		lookingForIndex = subtle.ConstantTimeSelect(equals0, 0, lookingForIndex)
	}

	if firstByteIsTwo != 1 || lookingForIndex != 0 || index < 9 {
		return nil, ErrDecrypt
	}
	return em[index+1:], nil

}

func hc(alg func() hash.Hash, ints ...*big.Int) *big.Int {
	h := alg()
	for _, n := range ints {
		_, _ = h.Write(n.Bytes())
	}
	return new(big.Int).SetBytes(h.Sum(nil))
}

// nonZeroRandomBytes fills the given slice with non-zero random octets.
func nonZeroRandomBytes(s []byte, rand io.Reader) (err error) {
	_, err = io.ReadFull(rand, s)
	if err != nil {
		return
	}

	for i := 0; i < len(s); i++ {
		for s[i] == 0 {
			_, err = io.ReadFull(rand, s[i:i+1])
			if err != nil {
				return
			}
		}
	}

	return
}
