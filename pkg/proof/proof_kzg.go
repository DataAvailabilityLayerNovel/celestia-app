package proof

import (
	"fmt"

	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
)

// KZGMultiProof represents a KZG polynomial commitment proof for a range of shares
// in a column. It proves that specific shares belong to the polynomial represented
// by a column commitment via the KZG polynomial commitment scheme.
//
// The proof consists of a single G1 point (the quotient polynomial commitment),
// which when used with pairing verification can confirm that the shares satisfy
// the column polynomial commitment.
type KZGMultiProof struct {
	// Proof is the G1 point representing the commited quotient polynomial Q(x).
	// This is the result of committing to the quotient Q(x) = [L(x) - I_S(x)] / Z_S(x)
	// Where L(x) is the interpolation polynomial of the shares and Z_S(x) is the
	// vanishing polynomial for the namespace range.
	// Serialized in compressed form (48 bytes for BN254).
	Proof *bn254.G1Affine `json:"proof"`
}

// CommitmentProof proves that column commitments belong to the data root.
// This replaces the old RowProof's role in proving row/column inclusion to the root.
//
// The proof demonstrates that specific column commitments from the data square
// commit to shares that are correctly included in the data root commitment.
type CommitmentProof struct {
	// ColumnProofs contains KZG proofs for each column commitment.
	// These prove that each column commitment satisfies the polynomial relationship
	// with the namespace range being queried.
	ColumnProofs []*KZGMultiProof

	// ColumnIndices contains the indices of columns being proven.
	// Used to identify which columns in the EDS are included in this proof.
	ColumnIndices []uint32

	// RootCommitment is the data root as a point commitment.
	// Optional, for verification purposes. Represents the root of the
	// commitment tree over all column commitments.
	RootCommitment *bn254.G1Affine
}

// PolynomialInterpolation represents a polynomial interpolated from shares.
// Used internally for KZG proof generation.
type PolynomialInterpolation struct {
	// Coefficients are the polynomial coefficients in the scalar field
	// indexed from lowest degree to highest degree.
	Coefficients []fr.Element
}

// VanishingPolynomial represents the polynomial that vanishes on a set of points.
// Used to create the quotient polynomial for KZG proofs.
type VanishingPolynomial struct {
	// Roots are the field elements where this polynomial evaluates to zero.
	// For a namespace range [start, end], roots are typically the indices
	// within that range represented as field elements.
	Roots []fr.Element

	// Coefficients are the polynomial coefficients (computed from roots).
	// In the form Z_S(x) = (x - r_0)(x - r_1)...(x - r_n)
	Coefficients []fr.Element
}

// QuotientPolynomial represents Q(x) = [L(x) - I_S(x)] / Z_S(x)
// where L(x) is the data polynomial, I_S(x) is the interpolation at range S,
// and Z_S(x) is the vanishing polynomial for range S.
type QuotientPolynomial struct {
	// Coefficients of the quotient polynomial
	Coefficients []fr.Element
}

// ShareToCellEvaluations maps a share's content to field element evaluations.
// This is used when converting raw share bytes to polynomial evaluations.
type ShareToCellEvaluations struct {
	// ShareIndex is the index of the share in the original data square
	ShareIndex int

	// Evaluations are the field element representations of the share's cell values
	Evaluations []fr.Element
}

// InterpolationDomain represents the domain points used for polynomial interpolation.
// For KZG proofs over a column, we interpolate at specific indices.
type InterpolationDomain struct {
	// Points are the field elements representing the evaluation points
	// Typically these are the share indices in the column that contain data for the namespace
	Points []fr.Element

	// Size is the number of points in the domain
	Size int
}

// NamespaceRange represents a range of shares belonging to a namespace in the data square.
// Used by KZG proof code to identify which cells need to be proven.
type NamespaceRange struct {
	// StartCell is the index of the first cell (share) in the ODS containing this namespace
	StartCell int

	// EndCell is the end-exclusive index of the last cell in the ODS containing this namespace
	// (following the convention that ranges are end-exclusive)
	EndCell int
}

// CellCoordinates represents the row and column coordinates of a cell in the data square.
type CellCoordinates struct {
	// Row is the row index in the EDS (0 to 2*squareSize-1 for extended square)
	Row int

	// Column is the column index in the current row
	Column int

	// IsOriginal indicates if this cell is in the original data square (true) or
	// in the erasure-coded extension rows (false)
	IsOriginal bool
}

// PolynomialCommitment represents a KZG commitment to a polynomial.
// This is typically a G1 point on the BN254 curve.
type PolynomialCommitment struct {
	// Point is the G1 point representing the commitment
	Point *bn254.G1Affine
}

// PairingVerificationInput represents the inputs needed for KZG pairing verification.
// Uses the check: e(π, [Z]_2) = e(C - [I]_1, [1]_2)
type PairingVerificationInput struct {
	// Proof is the quotient polynomial commitment (G1 point)
	Proof *bn254.G1Affine

	// ColumnCommitment is the column polynomial commitment (G1 point)
	ColumnCommitment *bn254.G1Affine

	// InterpolationCommitment is the commitment to I_S(x) (G1 point)
	InterpolationCommitment *bn254.G1Affine

	// VanishingPolyCommitment is the commitment to Z_S(x) at a setup point (G2 point)
	VanishingPolyCommitment *bn254.G2Affine
}

// ErrInvalidRange is returned when a namespace range is invalid
type ErrInvalidRange struct {
	StartCell int
	EndCell   int
	Message   string
}

func (e ErrInvalidRange) Error() string {
	return fmt.Sprintf("invalid range [%d, %d): %s", e.StartCell, e.EndCell, e.Message)
}

// ErrPolynomialException is returned when polynomial operations fail
type ErrPolynomialException struct {
	Operation string
	Details   string
}

func (e ErrPolynomialException) Error() string {
	return fmt.Sprintf("polynomial operation failed (%s): %s", e.Operation, e.Details)
}

// ErrPairingVerificationFailed is returned when KZG pairing verification fails
type ErrPairingVerificationFailed struct {
	ColumnIndex int
	Details     string
}

func (e ErrPairingVerificationFailed) Error() string {
	return fmt.Sprintf("pairing verification failed for column %d: %s", e.ColumnIndex, e.Details)
}

// NewKZGMultiProof creates a new KZG proof with the given quotient polynomial commitment.
func NewKZGMultiProof(proofPoint *bn254.G1Affine) *KZGMultiProof {
	return &KZGMultiProof{
		Proof: proofPoint,
	}
}

// NewCommitmentProof creates a new commitment proof.
func NewCommitmentProof(columnProofs []*KZGMultiProof, columnIndices []uint32, rootCommitment *bn254.G1Affine) *CommitmentProof {
	return &CommitmentProof{
		ColumnProofs:   columnProofs,
		ColumnIndices:  columnIndices,
		RootCommitment: rootCommitment,
	}
}

// NewNamespaceRange creates a new namespace range.
func NewNamespaceRange(startCell, endCell int) (NamespaceRange, error) {
	if startCell < 0 {
		return NamespaceRange{}, ErrInvalidRange{
			StartCell: startCell,
			EndCell:   endCell,
			Message:   "start cell must be non-negative",
		}
	}
	if endCell <= startCell {
		return NamespaceRange{}, ErrInvalidRange{
			StartCell: startCell,
			EndCell:   endCell,
			Message:   "end  cell must be greater than start cell",
		}
	}
	return NamespaceRange{
		StartCell: startCell,
		EndCell:   endCell,
	}, nil
}

// Size returns the number of cells in this namespace range.
func (nr NamespaceRange) Size() int {
	return nr.EndCell - nr.StartCell
}
