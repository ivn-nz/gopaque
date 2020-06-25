package gopaque

import (
	"bytes"
	"crypto/sha256"
	"encoding"
	"io"

	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/xof/blake2xb"
)

// toBytes assumes the given value should not fail to marshal.
func toBytes(s encoding.BinaryMarshaler) []byte {
	// Panic on err
	b, err := s.MarshalBinary()
	if err != nil {
		panic(err)
	}
	return b
}

func pubKey(c Crypto, priv kyber.Scalar) kyber.Point {
	return c.Point().Mul(priv, nil)
}

// readerStream is a simple utility to turn a io.Reader into a cipher.Stream.
type readerStream struct {
	io.Reader
}

// XORKeyStream implements cipher.Stream.XORKeyStream.
func (r *readerStream) XORKeyStream(dst, src []byte) {
	// Similar to the Kyber random stream...
	l := len(src)
	if len(dst) < l {
		panic("dst too short")
	}

	// Perform a simple XOR
	//r.XORSimple(l, dst, src)

	// Perform a XOR based on blake2b
	// reference from: https://github.com/dedis/kyber/blob/v3.0.x/util/random/rand.go
	r.XORBlake2b(dst, src)
}

// XORSimple create the output by simply xoring a key with the data
func (r *readerStream) XORSimple(l int, dst, src []byte) {
	buffKey := make([]byte, 32)
	_, err := io.ReadFull(r, buffKey)
	if err != nil {
		panic("reader failed")
	}

	for i := 0; i < l; i++ {
		dst[i] = src[i] ^ buffKey[i]
	}

}

func (r *readerStream) XORBlake2b(dst, src []byte) {
	// readerBytes is how many bytes we expect from each source
	readerBytes := 32

	// try to read readerBytes bytes from all readers and write them in a buffer
	var b bytes.Buffer

	buff := make([]byte, readerBytes)

	n, err := io.ReadFull(r.Reader, buff)
	if err != nil {
		panic("reader failed")
	}
	b.Write(buff[:n])

	// create the XOF output, with hash of collected data as seed
	h := sha256.New()
	h.Write(b.Bytes())
	seed := h.Sum(nil)
	blake2 := blake2xb.New(seed)
	blake2.XORKeyStream(dst, src)
}
