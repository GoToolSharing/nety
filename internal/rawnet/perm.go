package rawnet

import "math/bits"

// Permutation is a keyed pseudo-random bijection over [0, n), computed with
// O(1) memory (blackrock-style). It is a balanced Feistel network over the
// smallest even-bit-width power-of-two domain >= n, combined with cycle
// walking to stay inside [0, n). Scanners use it to visit huge (host x port)
// spaces in a randomized order without materialising the space:
//
//	for i := uint64(0); i < p.Len(); i++ { idx := p.At(i); host, port := idx/P, idx%P }
//
// The expected number of Feistel evaluations per At call is < 4.
type Permutation struct {
	n      uint64
	half   uint
	mask   uint64
	keys   [feistelRounds]uint64
	single bool // n <= 1 or tiny: identity mapping
}

const feistelRounds = 6

// NewPermutation returns a permutation of [0, n) keyed by seed. Distinct seeds
// give independent orders (use a different seed per retry round).
func NewPermutation(n, seed uint64) *Permutation {
	p := &Permutation{n: n}
	if n <= 2 {
		p.single = true
		return p
	}
	w := uint(bits.Len64(n - 1))
	if w%2 == 1 {
		w++
	}
	if w < 2 {
		w = 2
	}
	p.half = w / 2
	p.mask = (uint64(1) << p.half) - 1
	s := seed
	for i := range p.keys {
		s = splitmix64(s + uint64(i)*0x9e3779b97f4a7c15)
		p.keys[i] = s
	}
	return p
}

// Len is the size of the permuted domain.
func (p *Permutation) Len() uint64 { return p.n }

// At returns the i-th element of the permutation, i in [0, Len()). The
// result for i >= Len() is unspecified.
func (p *Permutation) At(i uint64) uint64 {
	if p.single {
		return i
	}
	x := p.encrypt(i)
	for x >= p.n {
		x = p.encrypt(x)
	}
	return x
}

func (p *Permutation) encrypt(x uint64) uint64 {
	l := x >> p.half
	r := x & p.mask
	for _, k := range p.keys {
		l, r = r, l^(splitmix64(r^k)&p.mask)
	}
	return l<<p.half | r
}

func splitmix64(x uint64) uint64 {
	x += 0x9e3779b97f4a7c15
	x = (x ^ x>>30) * 0xbf58476d1ce4e5b9
	x = (x ^ x>>27) * 0x94d049bb133111eb
	return x ^ x>>31
}
