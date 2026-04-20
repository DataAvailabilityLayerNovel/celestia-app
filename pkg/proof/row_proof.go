package proof

import (
	"errors"

	"github.com/cometbft/cometbft/crypto/merkle"
)

// Proof is an internal Merkle inclusion proof used by KZG range proof wiring.
type Proof struct {
	Total    int64
	Index    int64
	LeafHash []byte
	Aunts    [][]byte
}

// NMTProof is kept as an internal type for legacy helper compatibility.
type NMTProof struct {
	Start    int32
	End      int32
	Nodes    [][]byte
	LeafHash []byte
}

func (p *Proof) Verify(rootHash, leaf []byte) error {
	if p == nil {
		return errors.New("nil merkle proof")
	}
	proof := &merkle.Proof{
		Total:    p.Total,
		Index:    p.Index,
		LeafHash: p.LeafHash,
		Aunts:    p.Aunts,
	}
	return proof.Verify(rootHash, leaf)
}
