package da

import (
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"

	rsmt2d "github.com/DataAvailabilityLayerNovel/rlnc-rsmt2d"
	cda "github.com/DataAvailabilityLayerNovel/rlnc-rsmt2d/cda"
	rlnc "github.com/DataAvailabilityLayerNovel/rlnc-rsmt2d/rlnc"
	"github.com/celestiaorg/celestia-app/v8/pkg/appconsts"
	v5 "github.com/celestiaorg/celestia-app/v8/pkg/appconsts/v5"
	"github.com/celestiaorg/celestia-app/v8/pkg/wrapper"
	daproto "github.com/celestiaorg/celestia-app/v8/proto/celestia/core/v1/da"
	squarev2 "github.com/celestiaorg/go-square/v2"
	sharev2 "github.com/celestiaorg/go-square/v2/share"
	squarev3 "github.com/celestiaorg/go-square/v3"
	sharev3 "github.com/celestiaorg/go-square/v3/share"
	squarev4 "github.com/celestiaorg/go-square/v4"
	sharev4 "github.com/celestiaorg/go-square/v4/share"
	"github.com/cometbft/cometbft/crypto/merkle"
	"github.com/cometbft/cometbft/types"
	bls12381kzg "github.com/consensys/gnark-crypto/ecc/bls12-381/kzg"
)

var (
	maxExtendedSquareWidth = appconsts.SquareSizeUpperBound * 2
	minExtendedSquareWidth = appconsts.MinSquareSize * 2
)

// DataAvailabilityHeader (DAHeader) contains the commitments of the erasure coded
// version of the data in Block.Data. The original Block.Data is split into shares
// and arranged in a square of width squareSize. Then, this square is "extended"
// into an extended data square (EDS) of width 2*squareSize by applying Reed-Solomon
// encoding. Kate commitments are computed for each piece and combined for each column.
// For details see the Celestia specification:
// https://github.com/celestiaorg/celestia-specs/blob/master/src/specs/data_structures.md#availabledataheader
type DataAvailabilityHeader struct {
	// PieceComm contains N*k Kate commitments for each piece of the EDS
	// where N is the number of columns and k is the max chunks per column
	PieceComm [][]byte `json:"piece_commitments"`
	// ColumnComm contains N Kate commitments, one for each combined column
	ColumnComm [][]byte `json:"column_commitments"`
	// NamespaceIndex maps a namespace ID to its end-exclusive share range in the
	// original data square.
	NamespaceIndex map[string]sharev4.Range `json:"namespace_index,omitempty"`
	// hash is the root of all commitments. This field is the memoized result from `Hash()`.
	hash []byte
}

// NewDataAvailabilityHeader generates a DataAvailability header using the
// provided extended data square and its Kate commitments.
func NewDataAvailabilityHeader(eds *rsmt2d.ExtendedDataSquare) (DataAvailabilityHeader, error) {
	if eds == nil {
		return DataAvailabilityHeader{}, fmt.Errorf("eds is nil")
	}
	// d, err := randomCoefficientSeed()
	// if err != nil {
	// 	return DataAvailabilityHeader{}, fmt.Errorf("failed to generate coefficient seed: %w", err)
	// }

	// Need a function to initial
	d := 2810
	codec := rlnc.NewRLNCCodec(4)
	srsSize := uint64(eds.Width() * 4)
	srs, err := bls12381kzg.NewSRS(srsSize, big.NewInt(-1))
	if err != nil {
		return DataAvailabilityHeader{}, fmt.Errorf("failed to create KZG SRS: %w", err)
	}
	provider := cda.NewGnarkKZG(*srs)

	publishData, err := cda.ComputeAndSetKateCommitments(codec, eds, provider, d)
	if err != nil {
		return DataAvailabilityHeader{}, fmt.Errorf("failed to get Kate commitments: %w", err)
	}
	pieceComm := publishData.PieceComm
	columnComm := publishData.ColumnComm
	// Convert commitments to byte slices
	pieceCommBytes := make([][]byte, len(pieceComm))
	for i, comm := range pieceComm {
		pieceCommBytes[i] = append([]byte(nil), comm...)
	}

	columnCommBytes := make([][]byte, len(columnComm))
	for i, comm := range columnComm {
		columnCommBytes[i] = append([]byte(nil), comm...)
	}

	namespaceIndex, err := buildNamespaceIndexFromEDS(eds)
	if err != nil {
		return DataAvailabilityHeader{}, err
	}

	dah := DataAvailabilityHeader{
		PieceComm:      pieceCommBytes,
		ColumnComm:     columnCommBytes,
		NamespaceIndex: namespaceIndex,
	}

	// Generate the hash of the data using the new commitments
	dah.Hash()

	return dah, nil
}

func randomCoefficientSeed() (int, error) {
	maxInt := new(big.Int).SetUint64(^uint64(0) >> 1)
	seed, err := rand.Int(rand.Reader, maxInt)
	if err != nil {
		return 0, err
	}

	value := int(seed.Int64())
	if value == 0 {
		value = 1
	}

	return value, nil
}

// ConstructEDS constructs an ExtendedDataSquare from the given transactions and app version.
// If maxSquareSize is less than 0, it will use the upper bound square size for the given app version.
func ConstructEDS(txs [][]byte, appVersion uint64, maxSquareSize int) (*rsmt2d.ExtendedDataSquare, error) {
	switch appVersion {
	case 0:
		return nil, fmt.Errorf("app version cannot be 0")
	case 1, 2, 3, 4, 5: // versions 1-5 are all compatible with v2 of the square package
		if maxSquareSize < 0 {
			maxSquareSize = v5.SquareSizeUpperBound
		}
		// all versions 5 and below have the same parameters and algorithm
		square, err := squarev2.Construct(txs, maxSquareSize, v5.SubtreeRootThreshold)
		if err != nil {
			return nil, err
		}
		return ExtendShares(sharev2.ToBytes(square))
	case 6, 7: // versions 6-7 are compatible with v3 of the square package
		if maxSquareSize < 0 {
			maxSquareSize = appconsts.SquareSizeUpperBound
		}
		square, err := squarev3.Construct(txs, maxSquareSize, appconsts.SubtreeRootThreshold)
		if err != nil {
			return nil, err
		}
		return ExtendShares(sharev3.ToBytes(square))
	default: // assume all other versions are compatible with v4 of the square package
		if maxSquareSize < 0 {
			maxSquareSize = appconsts.SquareSizeUpperBound
		}
		square, err := squarev4.Construct(txs, maxSquareSize, appconsts.SubtreeRootThreshold)
		if err != nil {
			return nil, err
		}
		return ExtendShares(sharev4.ToBytes(square))
	}
}

// ConstructEDSWithTreePool constructs an ExtendedDataSquare from the given transactions and app version,
// it uses treePool to optimize allocations.
// If maxSquareSize is less than 0, it will use the upper bound square size for the given app version.
func ConstructEDSWithTreePool(txs [][]byte, appVersion uint64, maxSquareSize int, treePool *wrapper.TreePool) (*rsmt2d.ExtendedDataSquare, error) {
	switch appVersion {
	case 0:
		return nil, fmt.Errorf("app version cannot be 0")
	case 1, 2, 3, 4, 5: // versions 1-5 are all compatible with v2 of the square package
		if maxSquareSize < 0 {
			maxSquareSize = v5.SquareSizeUpperBound
		}
		// all versions 5 and below have the same parameters and algorithm
		square, err := squarev2.Construct(txs, maxSquareSize, v5.SubtreeRootThreshold)
		if err != nil {
			return nil, err
		}
		return ExtendSharesWithTreePool(sharev2.ToBytes(square), treePool)
	case 6, 7: // versions 6-7 are compatible with v3 of the square package
		if maxSquareSize < 0 {
			maxSquareSize = appconsts.SquareSizeUpperBound
		}
		square, err := squarev3.Construct(txs, maxSquareSize, appconsts.SubtreeRootThreshold)
		if err != nil {
			return nil, err
		}
		return ExtendSharesWithTreePool(sharev3.ToBytes(square), treePool)
	default: // assume all other versions are compatible with v4 of the square package
		if maxSquareSize < 0 {
			maxSquareSize = appconsts.SquareSizeUpperBound
		}
		square, err := squarev4.Construct(txs, maxSquareSize, appconsts.SubtreeRootThreshold)
		if err != nil {
			return nil, err
		}
		return ExtendSharesWithTreePool(sharev4.ToBytes(square), treePool)
	}
}

func ExtendShares(s [][]byte) (*rsmt2d.ExtendedDataSquare, error) {
	// Check that the length of the square is a power of 2.
	if !squarev4.IsPowerOfTwo(len(s)) {
		return nil, fmt.Errorf("number of shares is not a power of 2: got %d", len(s))
	}
	squareSize, err := squarev4.Size(len(s))
	if err != nil {
		return nil, err
	}

	// here we construct a tree
	// Note: uses the nmt wrapper to construct the tree.
	baseConstructor := wrapper.NewConstructor(uint64(squareSize))
	constructor := rsmt2d.TreeConstructorFn(func(axis rsmt2d.Axis, index uint) rsmt2d.Tree {
		tree := baseConstructor(rsmt2d.Axis(axis), index)
		adaptedTree, ok := any(tree).(rsmt2d.Tree)
		if !ok {
			panic(fmt.Sprintf("incompatible tree type: %T", tree))
		}
		return adaptedTree
	})
	return rsmt2d.ComputeExtendedDataSquare(s, appconsts.DefaultCodec(), constructor)
}

// ExtendSharesWithTreePool injects tree pool into rsmt2d to reuse allocs in root computation
func ExtendSharesWithTreePool(s [][]byte, treePool *wrapper.TreePool) (*rsmt2d.ExtendedDataSquare, error) {
	// Check that the length of the square is a power of 2.
	if !squarev4.IsPowerOfTwo(len(s)) {
		return nil, fmt.Errorf("number of shares is not a power of 2: got %d", len(s))
	}
	// here we construct a tree
	// Note: uses the nmt wrapper to construct the tree.
	constructor := rsmt2d.TreeConstructorFn(func(axis rsmt2d.Axis, index uint) rsmt2d.Tree {
		tree := treePool.NewConstructor(index)(rsmt2d.Axis(axis), index)
		adaptedTree, ok := any(tree).(rsmt2d.Tree)
		if !ok {
			panic(fmt.Sprintf("incompatible tree type: %T", tree))
		}
		return adaptedTree
	})

	bufferedConstructor := struct {
		rsmt2d.TreeConstructorFn
		treePool *wrapper.TreePool
	}{
		TreeConstructorFn: constructor,
		treePool:          treePool,
	}

	// Create a wrapper that implements BufferedTreeConstructor
	adaptedTreePool := &adaptedBufferedConstructor{
		treePool: bufferedConstructor.treePool,
	}
	return rsmt2d.ComputeExtendedDataSquareWithBuffer(s, appconsts.DefaultCodec(), adaptedTreePool)
}

type adaptedBufferedConstructor struct {
	treePool *wrapper.TreePool
}

func (a *adaptedBufferedConstructor) NewConstructor(squareSize uint) rsmt2d.TreeConstructorFn {
	return rsmt2d.TreeConstructorFn(func(axis rsmt2d.Axis, index uint) rsmt2d.Tree {
		tree := a.treePool.NewConstructor(squareSize)(rsmt2d.Axis(axis), index)
		adaptedTree, ok := any(tree).(rsmt2d.Tree)
		if !ok {
			panic(fmt.Sprintf("incompatible tree type: %T", tree))
		}
		return adaptedTree
	})
}

func (a *adaptedBufferedConstructor) TreeCount() int {
	return a.treePool.TreeCount()
}

/*// TreeConstructorFn creates a fresh Tree instance to be used as the Merkle tree
// inside of rsmt2d.
type TreeConstructorFn = func(axis Axis, index uint) Tree

type BufferedTreeConstructor interface {
	NewConstructor(squareSize uint) TreeConstructorFn
	TreeCount() int
}

// SquareIndex contains all information needed to identify the cell that is being
// pushed
type SquareIndex struct {
	Axis, Cell uint
}

// Tree wraps Merkle tree implementations to work with rsmt2d
type Tree interface {
	Push(data []byte) error
	Root() ([]byte, error)
}

var _ Tree = &DefaultTree{}

type DefaultTree struct {
	*merkletree.Tree
	leaves [][]byte
	root   []byte
}

func NewDefaultTree(_ Axis, _ uint) Tree {
	return &DefaultTree{
		Tree:   merkletree.New(sha256.New()),
		leaves: make([][]byte, 0, 128),
	}
}
*/

// String returns hex representation of merkle hash of the DAHeader.
func (dah *DataAvailabilityHeader) String() string {
	if dah == nil {
		return "<nil DAHeader>"
	}
	return fmt.Sprintf("%X", dah.Hash())
}

// Hash computes the Merkle root of all piece and column commitments.
// Hash memoizes the result in `DataAvailabilityHeader.hash`.
func (dah *DataAvailabilityHeader) Hash() []byte {
	if dah == nil {
		return merkle.HashFromByteSlices(nil)
	}
	if len(dah.hash) != 0 {
		return dah.hash
	}

	// Combine all commitments (piece + column) for hashing
	allComms := make([][]byte, 0, len(dah.ColumnComm))
	allComms = append(allComms, dah.ColumnComm...)

	// The single data root is computed using a binary merkle tree across all commitments
	dah.hash = merkle.HashFromByteSlices(allComms)
	return dah.hash
}

func (dah *DataAvailabilityHeader) ToProto() (*daproto.DataAvailabilityHeader, error) {
	if dah == nil {
		return nil, errors.New("nil DataAvailabilityHeader")
	}

	dahp := new(daproto.DataAvailabilityHeader)
	dahp.RowRoots = dah.ColumnComm    // Legacy: use column commitments as row roots
	dahp.ColumnRoots = dah.ColumnComm // Keep column commitments
	return dahp, nil
}

func DataAvailabilityHeaderFromProto(dahp *daproto.DataAvailabilityHeader) (dah *DataAvailabilityHeader, err error) {
	if dahp == nil {
		return nil, errors.New("nil DataAvailabilityHeader")
	}

	dah = new(DataAvailabilityHeader)
	// For now, load from proto's column roots (legacy compatibility)
	dah.ColumnComm = dahp.ColumnRoots

	return dah, dah.ValidateBasic()
}

// ValidateBasic runs stateless checks on the DataAvailabilityHeader.
func (dah *DataAvailabilityHeader) ValidateBasic() error {
	if dah == nil {
		return errors.New("nil data availability header is not valid")
	}
	if len(dah.ColumnComm) < minExtendedSquareWidth {
		return fmt.Errorf(
			"minimum valid DataAvailabilityHeader has at least %d column commitments",
			minExtendedSquareWidth,
		)
	}
	if len(dah.ColumnComm) > maxExtendedSquareWidth {
		return fmt.Errorf(
			"maximum valid DataAvailabilityHeader has at most %d column commitments",
			maxExtendedSquareWidth,
		)
	}
	if err := types.ValidateHash(dah.Hash()); err != nil {
		return fmt.Errorf("wrong hash: %v", err)
	}

	return nil
}

// IsZero returns true if the DataAvailabilityHeader is nil or it has no column commitments.
func (dah *DataAvailabilityHeader) IsZero() bool {
	if dah == nil {
		return true
	}
	return len(dah.ColumnComm) == 0
}

// SquareSize returns the number of rows in the original data square.
// It is derived from the number of column commitments (which equals the extended square width / 2).
func (dah *DataAvailabilityHeader) SquareSize() int {
	return len(dah.ColumnComm) / 2
}

// MinDataAvailabilityHeader returns the minimum valid data availability header.
// It is equal to the data availability header for a block with one tail padding share.
func MinDataAvailabilityHeader() DataAvailabilityHeader {
	s := MinShares()
	eds, err := ExtendShares(s)
	if err != nil {
		panic(err)
	}
	dah, err := NewDataAvailabilityHeader(eds)
	if err != nil {
		panic(err)
	}
	return dah
}

// MinShares returns one tail-padded share.
func MinShares() [][]byte {
	return sharev4.ToBytes(squarev4.EmptySquare())
}

// NamespaceRange returns the share range for the given namespace ID.
func (dah DataAvailabilityHeader) NamespaceRange(namespaceID []byte) (sharev4.Range, bool) {
	if len(dah.NamespaceIndex) == 0 {
		return sharev4.EmptyRange(), false
	}
	rangeValue, ok := dah.NamespaceIndex[string(namespaceID)]
	return rangeValue, ok
}

func buildNamespaceIndexFromEDS(eds *rsmt2d.ExtendedDataSquare) (map[string]sharev4.Range, error) {
	shares, err := sharev4.FromBytes(eds.FlattenedODS())
	if err != nil {
		return nil, fmt.Errorf("failed to decode flattened ODS shares: %w", err)
	}
	return buildNamespaceIndex(shares)
}

func buildNamespaceIndex(shares []sharev4.Share) (map[string]sharev4.Range, error) {
	if len(shares) == 0 {
		return nil, nil
	}

	index := make(map[string]sharev4.Range)
	start := 0
	currentNamespace := shares[0].Namespace()
	for i := 1; i < len(shares); i++ {
		nextNamespace := shares[i].Namespace()
		if currentNamespace.Equals(nextNamespace) {
			continue
		}

		key := string(currentNamespace.Bytes())
		if _, exists := index[key]; exists {
			return nil, fmt.Errorf("namespace %x appears in multiple non-contiguous ranges", currentNamespace.Bytes())
		}
		index[key] = sharev4.NewRange(start, i)
		start = i
		currentNamespace = nextNamespace
	}

	key := string(currentNamespace.Bytes())
	if _, exists := index[key]; exists {
		return nil, fmt.Errorf("namespace %x appears in multiple non-contiguous ranges", currentNamespace.Bytes())
	}
	index[key] = sharev4.NewRange(start, len(shares))
	return index, nil
}
