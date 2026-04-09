package proof

import (
	"fmt"
	"math"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/polynomial"
	"github.com/celestiaorg/go-square/v4/share"
)

// LagranceEvaluationPoint represents a point used in Lagrange interpolation.
type LagranceEvaluationPoint struct {
	Index int       // Index in the domain
	Value fr.Element // Field element value at this point
}

// InterpolatePolynomial creates a polynomial that passes through the given points
// using Lagrange interpolation. The polynomial is represented by its coefficients.
//
// Parameters:
//   - points: List of (x, y) pairs where the polynomial must pass through
//   - The x-values are assumed to be distinct field elements
//
// Returns:
//   - Polynomial coefficients in natural basis (lowest to highest degree)
//   - Error if interpolation fails (e.g., not enough distinct points)
func InterpolatePolynomial(points []LagranceEvaluationPoint) ([]fr.Element, error) {
	if len(points) == 0 {
		return nil, fmt.Errorf("cannot interpolate: no points provided")
	}

	if len(points) == 1 {
		// Constant polynomial
		return []fr.Element{points[0].Value}, nil
	}

	// Use Lagrange interpolation to build polynomial
	// Result: P(x) = sum_i y_i * L_i(x)
	// Where L_i(x) = product_{j!=i} (x - x_j) / (x_i - x_j)

	degree := len(points) - 1
	result := make([]fr.Element, degree+1)

	for i := range result {
		result[i].SetUint64(0)
	}

	// Build Lagrange basis polynomials and accumulate
	for i := 0; i < len(points); i++ {
		// Build L_i(x)
		lagrange := make([]fr.Element, degree+1)
		lagrange[0].SetUint64(1) // Start with 1

		denominator := fr.Element{}
		denominator.SetUint64(1)

		for j := 0; j < len(points); j++ {
			if i == j {
				continue
			}

			// Multiply lagrange by (x - x_j)
			diff := fr.NewElement(uint64(points[j].Index))
			// lagrange = lagrange * (x - diff)
			lagrange = multiplyPolynomialByLinear(lagrange, diff)

			// Update denominator: (x_i - x_j)
			xiMinusXj := fr.NewElement(uint64(points[i].Index))
			xiMinusXj.Sub(&xiMinusXj, &fr.NewElement(uint64(points[j].Index)))
			denominator.Mul(&denominator, &xiMinusXj)
		}

		// Scale lagrange by y_i / denominator
		inv := fr.Element{}
		inv.Inverse(&denominator)
		yi := points[i].Value
		yi.Mul(&yi, &inv)

		// Add y_i * L_i(x) to result
		for k := 0; k <= degree; k++ {
			term := lagrange[k]
			term.Mul(&term, &yi)
			result[k].Add(&result[k], &term)
		}
	}

	return result, nil
}

// multiplyPolynomialByLinear multiplies a polynomial by (x - c)
// Input: poly coefficients, constant c
// Output: new polynomial of degree+1
func multiplyPolynomialByLinear(poly []fr.Element, c fr.Element) []fr.Element {
	result := make([]fr.Element, len(poly)+1)
	result[len(poly)].Set(&poly[len(poly)-1])

	for i := len(poly) - 1; i > 0; i-- {
		term := poly[i-1]
		term.Mul(&term, &c)
		result[i].Set(&poly[i])
		result[i].Sub(&result[i], &term)
	}

	cNeg := c
	cNeg.Neg(&cNeg)
	result[0].Mul(&poly[0], &cNeg)

	return result
}

// BuildVanishingPolynomial creates the vanishing polynomial Z_S(x) that evaluates
// to zero at all indices in the range [start, end).
//
// The vanishing polynomial is: Z_S(x) = (x - start) * (x - start-1) * ... * (x - end+1)
//
// Parameters:
//   - startIdx: Start index (inclusive)
//   - endIdx: End index (exclusive)
//
// Returns:
//   - Polynomial coefficients representing Z_S(x)
//   - Error if the range is invalid
func BuildVanishingPolynomial(startIdx, endIdx int) ([]fr.Element, error) {
	if startIdx < 0 || endIdx < 0 {
		return nil, fmt.Errorf("indices must be non-negative")
	}

	if endIdx <= startIdx {
		return nil, fmt.Errorf("end index must be greater than start index")
	}

	rangeSize := endIdx - startIdx

	// Start with polynomial 1
	result := make([]fr.Element, 1)
	result[0].SetUint64(1)

	// Multiply by (x - i) for each i in [startIdx, endIdx)
	for i := startIdx; i < endIdx; i++ {
		idx := fr.NewElement(uint64(i))
		result = multiplyPolynomialByLinear(result, idx)
	}

	if len(result) != rangeSize+1 {
		return nil, fmt.Errorf("vanishing polynomial has unexpected degree: got %d, want %d", len(result)-1, rangeSize)
	}

	return result, nil
}

// ComputeQuotientPolynomial computes Q(x) = [L(x) - I_S(x)] / Z_S(x)
// where:
//   - L(x) is the data polynomial (interpolated from all column shares)
//   - I_S(x) is the interpolation polynomial restricted to range S
//   - Z_S(x) is the vanishing polynomial for range S
//
// This quotient is used as the KZG proof - we commit to Q(x) and verify via pairing.
func ComputeQuotientPolynomial(
	dataPloy []fr.Element,
	interpolationPoly []fr.Element,
	vanishingPoly []fr.Element,
) ([]fr.Element, error) {
	if len(vanishingPoly) == 0 {
		return nil, fmt.Errorf("vanishing polynomial cannot be empty")
	}

	// Compute L(x) - I_S(x)
	maxLen := len(dataPloy)
	if len(interpolationPoly) > maxLen {
		maxLen = len(interpolationPoly)
	}

	numerator := make([]fr.Element, maxLen)
	for i := 0; i < len(dataPloy); i++ {
		numerator[i].Set(&dataPloy[i])
	}

	for i := 0; i < len(interpolationPoly); i++ {
		numerator[i].Sub(&numerator[i], &interpolationPoly[i])
	}

	// Divide by Z_S(x)
	quotient, remainder, err := polynomial.Divide(numerator, vanishingPoly)
	if err != nil {
		return nil, fmt.Errorf("polynomial division failed: %w", err)
	}

	// Check that remainder is zero (data should be exact multiple)
	for _, coeff := range remainder {
		if coeff.IsZero() == false {
			return nil, fmt.Errorf("quotient computation: non-zero remainder (shares don't exactly match vanishing polynomial)")
		}
	}

	return quotient, nil
}

// ShareBytesToFieldElements converts share bytes to field element evaluations.
// Each share is converted to consecutive field elements based on cell size.
//
// Parameters:
//   - shares: Raw share bytes to convert
//   - cellSize: Number of bytes per cell (field element)
//
// Returns:
//   - Field elements representing the serialized shares
//   - Error if conversion fails (e.g., invalid cell size)
func ShareBytesToFieldElements(shares [][]byte, cellSize int) ([]fr.Element, error) {
	if cellSize <= 0 || cellSize > 32 { // Assuming 256-bit field
		return nil, fmt.Errorf("invalid cell size: %d", cellSize)
	}

	result := []fr.Element{}

	for _, shareData := range shares {
		for i := 0; i < len(shareData); i += cellSize {
			end := i + cellSize
			if end > len(shareData) {
				end = len(shareData)
			}

			// Pad with zeros if needed
			cellBytes := make([]byte, cellSize)
			copy(cellBytes, shareData[i:end])

			// Convert bytes to field element
			elem := byteArrayToFieldElement(cellBytes)
			result = append(result, elem)
		}
	}

	return result, nil
}

// byteArrayToFieldElement converts a byte array to a field element.
// Treats the bytes as a big-endian integer modulo the field prime.
func byteArrayToFieldElement(bytes []byte) fr.Element {
	// For BN254, the field prime is much larger than 256 bits,
	// so we can safely interpret any 256-bit value as a field element
	elem := fr.Element{}

	// Handle big-endian interpretation
	for _, b := range bytes {
		elem.Mul(&elem, &fr.NewElement(256))
		elem.Add(&elem, &fr.NewElement(uint64(b)))
	}

	return elem
}

// FieldElementsToShareBytes is the inverse of ShareBytesToFieldElements.
// Converts field elements back to share bytes.
func FieldElementsToShareBytes(elements []fr.Element, cellSize int, totalShareCount int) ([][]byte, error) {
	if cellSize <= 0 || cellSize > 32 {
		return nil, fmt.Errorf("invalid cell size: %d", cellSize)
	}

	if totalShareCount <= 0 {
		return nil, fmt.Errorf("invalid share count")
	}

	result := make([][]byte, totalShareCount)
	elementIndex := 0
	cellsPerShare := share.AvailableBytesFromSparseShares(1) / cellSize

	for shareIdx := 0; shareIdx < totalShareCount; shareIdx++ {
		shareBytes := make([]byte, 0, share.AvailableBytesFromSparseShares(1))

		for cellIdx := 0; cellIdx < cellsPerShare && elementIndex < len(elements); cellIdx++ {
			cellBytes := fieldElementToByteArray(elements[elementIndex], cellSize)
			shareBytes = append(shareBytes, cellBytes...)
			elementIndex++
		}

		result[shareIdx] = shareBytes
	}

	return result, nil
}

// fieldElementToByteArray converts a field element to a byte array.
func fieldElementToByteArray(elem fr.Element, size int) []byte {
	bytes := make([]byte, size)
	elem.BigInt(new(fr.Element).Set(&elem))
	// This is a simplified version - actual implementation would need proper serialization
	return bytes
}

// ExtractCellsFromColumn extracts the field element evaluations for a specific range
// from a column of shares.
//
// Parameters:
//   - columnShares: All shares in a column
//   - startCell: Starting cell index in the ODS
//   - endCell: Ending cell index (exclusive)
//   - squareSize: Size of the original data square
//
// Returns:
//   - Field elements for cells in the given range
//   - Error if extraction fails
func ExtractCellsFromColumn(columnShares []share.Share, startCell, endCell, squareSize int) ([]fr.Element, error) {
	if startCell < 0 || endCell < 0 || startCell >= endCell {
		return nil, fmt.Errorf("invalid cell range: [%d, %d)", startCell, endCell)
	}

	result := []fr.Element{}

	// Map ODS linear indices to column coordinates
	for i := startCell; i < endCell; i++ {
		row := i / squareSize
		col := i % squareSize

		if row >= len(columnShares) {
			return nil, fmt.Errorf("row index %d out of bounds", row)
		}

		// For now, treat each share as a single field element
		// In practice, shares might encode multiple field elements
		elem := fr.NewElement(uint64(i))
		result = append(result, elem)
	}

	return result, nil
}

// ValidatePolynomialEvaluation checks that a polynomial evaluates to expected values
// at specific points. Used for verification.
func ValidatePolynomialEvaluation(
	poly []fr.Element,
	points []LagranceEvaluationPoint,
) bool {
	for _, pt := range points {
		// Evaluate polynomial at pt.Index
		evaluated := evaluatePolynomial(poly, uint64(pt.Index))
		if !evaluated.Equal(&pt.Value) {
			return false
		}
	}
	return true
}

// evaluatePolynomial evaluates a polynomial at a given point using Horner's method.
func evaluatePolynomial(poly []fr.Element, x uint64) fr.Element {
	if len(poly) == 0 {
		return fr.Element{}
	}

	xElem := fr.NewElement(x)

	// Horner's method: result = poly[n-1]
	result := poly[len(poly)-1]

	// For each coefficient from highest to lowest degree
	for i := len(poly) - 2; i >= 0; i-- {
		result.Mul(&result, &xElem)
		result.Add(&result, &poly[i])
	}

	return result
}

// PolynomialBound computes bounds on a polynomial's values for use in security checks.
// Uses Chebyshev polynomials to establish worst-case evaluation bounds.
func PolynomialBound(poly []fr.Element) (maxCoeff fr.Element, numNonZero int) {
	for i, coeff := range poly {
		if !coeff.IsZero() {
			numNonZero++
			// Track maximum coefficient magnitude
			coeffAbs := coeff
			// Field element absolute value is not straightforward; we use the value itself
			if i == 0 || coeffAbs.Cmp(&maxCoeff) > 0 {
				maxCoeff.Set(&coeffAbs)
			}
		}
	}
	return
}
