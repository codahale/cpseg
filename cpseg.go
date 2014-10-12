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
	"hash"
	"io"
	"math/big"
)

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
	M := new(big.Int).SetBytes(msg)

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
func Decrypt(priv *PrivateKey, Y, R, A, s *big.Int) []byte {
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
		return nil
	}

	return new(big.Int).Div(Y, Rprime).Bytes()
}

func hc(alg func() hash.Hash, ints ...*big.Int) *big.Int {
	h := alg()
	for _, n := range ints {
		_, _ = h.Write(n.Bytes())
	}
	return new(big.Int).SetBytes(h.Sum(nil))
}
