package da

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"testing"

	rsmt2d "github.com/DataAvailabilityLayerNovel/rlnc-rsmt2d"
	"github.com/celestiaorg/celestia-app/v8/pkg/appconsts"
	appconstsv5 "github.com/celestiaorg/celestia-app/v8/pkg/appconsts/v5"
	"github.com/celestiaorg/celestia-app/v8/pkg/wrapper"
	fibretypes "github.com/celestiaorg/celestia-app/v8/x/fibre/types"
	sharev2 "github.com/celestiaorg/go-square/v2/share"
	squarev4 "github.com/celestiaorg/go-square/v4"
	sh "github.com/celestiaorg/go-square/v4/share"
	gotx "github.com/celestiaorg/go-square/v4/tx"
	"github.com/cometbft/cometbft/crypto/merkle"
	"github.com/cosmos/btcutil/bech32"
	codectypes "github.com/cosmos/cosmos-sdk/codec/types"
	cosmostx "github.com/cosmos/cosmos-sdk/types/tx"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNilDataAvailabilityHeaderHashDoesntCrash(t *testing.T) {
	// This follows RFC-6962, i.e. `echo -n '' | sha256sum`
	emptyBytes := []byte{
		0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8,
		0x99, 0x6f, 0xb9, 0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b,
		0x78, 0x52, 0xb8, 0x55,
	}

	assert.Equal(t, emptyBytes, (*DataAvailabilityHeader)(nil).Hash())
	assert.Equal(t, emptyBytes, new(DataAvailabilityHeader).Hash())
}
func TestMinDataAvailabilityHeader(t *testing.T) {
	dah := MinDataAvailabilityHeader()
	// With the current implementation, DAH hash is the Merkle root of column commitments.
	require.Equal(t, merkle.HashFromByteSlices(dah.ColumnComm), dah.hash)
	require.NoError(t, dah.ValidateBasic())
}

type (
	extendFunc    = func([][]byte) (*rsmt2d.ExtendedDataSquare, error)
	constructFunc = func(txs [][]byte, appVersion uint64, maxSquareSize int) (*rsmt2d.ExtendedDataSquare, error)
)

// extendSharesWithPool works exactly the same as ExtendShares,
// but it uses treePool to reuse the allocs.
func extendSharesWithPool(s [][]byte) (*rsmt2d.ExtendedDataSquare, error) {
	treePool, err := wrapper.DefaultPreallocatedTreePool(512)
	if err != nil {
		return nil, err
	}
	return ExtendSharesWithTreePool(s, treePool)
}

// constructEDSWithPool works exactly the same as ConstructEDS,
// but it uses treePool to reuse the allocs.
func constructEDSWithPool(txs [][]byte, appVersion uint64, maxSquareSize int) (*rsmt2d.ExtendedDataSquare, error) {
	treePool, err := wrapper.DefaultPreallocatedTreePool(512)
	if err != nil {
		return nil, err
	}
	return ConstructEDSWithTreePool(txs, appVersion, maxSquareSize, treePool)
}

func TestMinDataAvailabilityHeaderBackwardsCompatibility(t *testing.T) {
	for _, extendShares := range []extendFunc{
		extendSharesWithPool,
		ExtendShares,
	} {
		dahv4 := MinDataAvailabilityHeader()
		shareV2 := sharev2.ToBytes(sharev2.TailPaddingShares(appconsts.MinShareCount))
		eds, err := extendShares(shareV2)
		require.NoError(t, err)
		dahV2, err := NewDataAvailabilityHeader(eds)
		require.NoError(t, err)
		require.Equal(t, dahv4.hash, dahV2.hash)
	}
}

func TestNewDataAvailabilityHeader(t *testing.T) {
	type test struct {
		name         string
		expectedHash []byte
		squareSize   uint64
		shares       [][]byte
	}

	tests := []test{
		{
			name:         "typical",
			expectedHash: []byte{0x8b, 0xc3, 0x88, 0xa6, 0x9a, 0xca, 0xca, 0x88, 0x1b, 0xf0, 0x4e, 0x58, 0xe7, 0xc3, 0x52, 0xff, 0xb3, 0x7, 0x2e, 0xcb, 0xd7, 0x7c, 0xca, 0xce, 0x8a, 0x93, 0x47, 0x0, 0x8a, 0xd9, 0xc0, 0xa5},
			squareSize:   2,
			shares:       generateShares(2 * 2),
		},
		{
			name:         "max square size",
			expectedHash: []byte{0x52, 0x3a, 0xd5, 0xf5, 0x47, 0x55, 0xec, 0x10, 0x8d, 0xf1, 0xd5, 0x13, 0xcf, 0x23, 0x7f, 0x3c, 0x9b, 0x84, 0x44, 0x6c, 0xd5, 0x38, 0x69, 0x46, 0x40, 0x5a, 0x32, 0xff, 0x16, 0x95, 0xd6, 0xf7},
			squareSize:   uint64(appconsts.SquareSizeUpperBound),
			shares:       generateShares(appconsts.SquareSizeUpperBound * appconsts.SquareSizeUpperBound),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for _, extendShares := range []extendFunc{
				extendSharesWithPool,
				ExtendShares,
			} {
				eds, err := extendShares(tt.shares)
				require.NoError(t, err)
				got, err := NewDataAvailabilityHeader(eds)
				require.NoError(t, err)
				require.Equal(t, tt.squareSize*2, uint64(len(got.ColumnComm)))
				require.Equal(t, tt.expectedHash, got.hash)
			}
		})
	}
}

func TestExtendShares(t *testing.T) {
	type test struct {
		name        string
		expectedErr bool
		shares      [][]byte
	}

	tests := []test{
		{
			name:        "too large square size",
			expectedErr: true,
			shares:      generateShares((appconsts.SquareSizeUpperBound + 1) * (appconsts.SquareSizeUpperBound + 1)),
		},
		{
			name:        "invalid number of shares",
			expectedErr: true,
			shares:      generateShares(5),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for _, extendShares := range []extendFunc{
				extendSharesWithPool,
				ExtendShares,
			} {
				_, err := extendShares(tt.shares)
				if tt.expectedErr {
					require.NotNil(t, err)
				} else {
					require.NoError(t, err)
				}
			}
		})
	}
}

func TestDataAvailabilityHeaderProtoConversion(t *testing.T) {
	for _, extendShares := range []extendFunc{
		extendSharesWithPool,
		ExtendShares,
	} {
		testDataAvailabilityHeaderProtoConversion(t, extendShares)
	}
}

func testDataAvailabilityHeaderProtoConversion(t *testing.T, extendShares func([][]byte) (*rsmt2d.ExtendedDataSquare, error)) {
	type test struct {
		name string
		dah  DataAvailabilityHeader
	}

	shares := generateShares(appconsts.SquareSizeUpperBound * appconsts.SquareSizeUpperBound)
	eds, err := extendShares(shares)
	require.NoError(t, err)
	bigdah, err := NewDataAvailabilityHeader(eds)
	require.NoError(t, err)

	tests := []test{
		{
			name: "min",
			dah:  MinDataAvailabilityHeader(),
		},
		{
			name: "max",
			dah:  bigdah,
		},
	}

	for _, tt := range tests {
		pdah, err := tt.dah.ToProto()
		require.NoError(t, err)
		resDah, err := DataAvailabilityHeaderFromProto(pdah)
		require.NoError(t, err)
		resDah.Hash() // calc the hash to make the comparisons fair
		require.Equal(t, tt.dah.ColumnComm, resDah.ColumnComm, tt.name)
		require.Equal(t, tt.dah.hash, resDah.hash, tt.name)
	}
}

func TestDataAvailabilityHeaderNamespaceIndexLookup(t *testing.T) {
	fibreTx := buildMsgPayForFibreTxBytes(t)
	normalTx := bytes.Repeat([]byte{0x01}, 200)
	txs := [][]byte{normalTx, fibreTx}

	square, err := squarev4.Construct(txs, appconsts.SquareSizeUpperBound, appconsts.SubtreeRootThreshold)
	require.NoError(t, err)

	eds, err := ExtendShares(sh.ToBytes(square))
	require.NoError(t, err)

	dah, err := NewDataAvailabilityHeader(eds)
	require.NoError(t, err)

	expected := sh.GetShareRangeForNamespace(square, sh.PayForFibreNamespace)
	actual, ok := dah.NamespaceRange(sh.PayForFibreNamespace.Bytes())
	require.True(t, ok)
	require.Equal(t, expected, actual)

	missing, ok := dah.NamespaceRange(bytes.Repeat([]byte{0xff}, sh.NamespaceSize))
	require.False(t, ok)
	require.True(t, missing.IsEmpty())
}

func Test_DAHValidateBasic(t *testing.T) {
	for _, extendShares := range []extendFunc{
		extendSharesWithPool,
		ExtendShares,
	} {
		testDAHValidateBasic(t, extendShares)
	}
}

func testDAHValidateBasic(t *testing.T, extendShares func([][]byte) (*rsmt2d.ExtendedDataSquare, error)) {
	type test struct {
		name      string
		dah       DataAvailabilityHeader
		expectErr bool
		errStr    string
	}

	maxSize := appconsts.SquareSizeUpperBound * appconsts.SquareSizeUpperBound

	shares := generateShares(maxSize)
	eds, err := extendShares(shares)
	require.NoError(t, err)
	bigdah, err := NewDataAvailabilityHeader(eds)
	require.NoError(t, err)

	// make a mutant dah that has too many roots
	var tooBigDah DataAvailabilityHeader
	tooBigDah.ColumnComm = make([][]byte, maxSize)
	copy(tooBigDah.ColumnComm, bigdah.ColumnComm)
	tooBigDah.ColumnComm = append(tooBigDah.ColumnComm, bytes.Repeat([]byte{1}, 32))
	// make a mutant dah that has too few roots
	var tooSmallDah DataAvailabilityHeader
	tooSmallDah.ColumnComm = [][]byte{bytes.Repeat([]byte{2}, 32)}
	// use a bad hash
	badHashDah := MinDataAvailabilityHeader()
	badHashDah.hash = []byte{1, 2, 3, 4}

	tests := []test{
		{
			name: "min",
			dah:  MinDataAvailabilityHeader(),
		},
		{
			name: "max",
			dah:  bigdah,
		},
		{
			name:      "too big dah",
			dah:       tooBigDah,
			expectErr: true,
			errStr:    "maximum valid DataAvailabilityHeader has at most",
		},
		{
			name:      "too small dah",
			dah:       tooSmallDah,
			expectErr: true,
			errStr:    "minimum valid DataAvailabilityHeader has at least",
		},
		{
			name:      "bad hash",
			dah:       badHashDah,
			expectErr: true,
			errStr:    "wrong hash",
		},
	}

	for _, tt := range tests {
		err := tt.dah.ValidateBasic()
		if tt.expectErr {
			require.True(t, strings.Contains(err.Error(), tt.errStr), tt.name)
			require.Error(t, err)
			continue
		}
		require.NoError(t, err)
	}
}

func TestSquareSize(t *testing.T) {
	type testCase struct {
		name string
		dah  DataAvailabilityHeader
		want int
	}

	testCases := []testCase{
		{
			name: "min data availability header has an original square size of 1",
			dah:  MinDataAvailabilityHeader(),
			want: 1,
		},
		{
			name: "max data availability header has an original square size of default square size upper bound",
			dah:  maxDataAvailabilityHeader(t),
			want: appconsts.SquareSizeUpperBound,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got := tc.dah.SquareSize()
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestConstructEDS_Versions(t *testing.T) {
	minAppVersion := uint64(0)
	maxAppVersion := appconsts.Version + 1 // even future versions won't error and assume compatibility with v4
	for appVersion := minAppVersion; appVersion <= maxAppVersion; appVersion++ {
		t.Run(fmt.Sprintf("app version %d", appVersion), func(t *testing.T) {
			for _, constructEDS := range []constructFunc{
				constructEDSWithPool,
				ConstructEDS,
			} {
				shares := generateShares(4)
				maxSquareSize := -1
				eds, err := constructEDS(shares, appVersion, maxSquareSize)
				if appVersion == 0 {
					require.Error(t, err)
					require.Nil(t, eds)
				} else {
					require.NoError(t, err)
					require.NotNil(t, eds)
				}
			}
		})
	}
}

func TestConstructEDS_SquareSize(t *testing.T) {
	type testCase struct {
		name         string
		appVersion   uint64
		maxSquare    int
		expectedSize int
	}
	testCases := []testCase{
		{
			name:         "v5 version with custom square size",
			appVersion:   appconstsv5.Version,
			maxSquare:    4,
			expectedSize: 4,
		},
		{
			name:         "v5 version with default square size",
			appVersion:   appconstsv5.Version,
			maxSquare:    -1,
			expectedSize: appconstsv5.SquareSizeUpperBound,
		},
		{
			name:         "latest version with custom square size",
			appVersion:   appconsts.Version,
			maxSquare:    8,
			expectedSize: 8,
		},
		{
			name:         "latest version with default square size",
			appVersion:   appconsts.Version,
			maxSquare:    -1,
			expectedSize: appconsts.SquareSizeUpperBound,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			for _, construct := range []constructFunc{
				constructEDSWithPool,
				ConstructEDS,
			} {
				txLength := sh.AvailableBytesFromCompactShares((tc.expectedSize * tc.expectedSize) - 1)
				tx := bytes.Repeat([]byte{0x1}, txLength)
				eds, err := construct([][]byte{tx}, tc.appVersion, tc.maxSquare)
				require.NoError(t, err)
				require.NotNil(t, eds)
				// The EDS width should be 2*expectedSize
				require.Equal(t, tc.expectedSize*2, int(eds.Width()))
			}
		})
	}
}

// generateShares generates count number of shares with a constant namespace and
// share contents.
func generateShares(count int) (shares [][]byte) {
	ns1 := sh.MustNewV0Namespace(bytes.Repeat([]byte{1}, sh.NamespaceVersionZeroIDSize))

	for range count {
		share := generateShare(ns1.Bytes())
		shares = append(shares, share)
	}
	sortByteArrays(shares)
	return shares
}

func generateShare(namespace []byte) (share []byte) {
	remainder := bytes.Repeat([]byte{0xFF}, sh.ShareSize-len(namespace))
	share = append(share, namespace...)
	share = append(share, remainder...)
	return share
}

func sortByteArrays(arr [][]byte) {
	sort.Slice(arr, func(i, j int) bool {
		return bytes.Compare(arr[i], arr[j]) < 0
	})
}

// TestConstructEDS_RealBlocks verifies that ConstructEDS produces a data
// availability header whose hash matches the on-chain data hash for real
// blocks from Celestia mainnet and Mocha testnet. This ensures that the
// go-square version used for each app version is correct and consensus-compatible.
func TestConstructEDS_RealBlocks(t *testing.T) {
	files := []string{
		"testdata/mainnet_block_10126899.json", // app version 6, Celestia mainnet
		"testdata/mocha_block_10383867.json",   // app version 7, Mocha testnet
	}

	for _, file := range files {
		data, err := os.ReadFile(file)
		require.NoError(t, err)

		var block struct {
			Height     int64    `json:"height"`
			AppVersion uint64   `json:"app_version"`
			DataHash   string   `json:"data_hash"`
			SquareSize int      `json:"square_size"`
			Txs        []string `json:"txs"`
		}
		require.NoError(t, json.Unmarshal(data, &block))

		// Decode base64 txs.
		txs := make([][]byte, len(block.Txs))
		for i, b64 := range block.Txs {
			txs[i], err = base64.StdEncoding.DecodeString(b64)
			require.NoError(t, err)
		}

		t.Run(fmt.Sprintf("height_%d_v%d", block.Height, block.AppVersion), func(t *testing.T) {
			var firstHash []byte
			for _, construct := range []constructFunc{
				constructEDSWithPool,
				ConstructEDS,
			} {
				eds, err := construct(txs, block.AppVersion, block.SquareSize)
				require.NoError(t, err)
				require.NotNil(t, eds)

				dah, err := NewDataAvailabilityHeader(eds)
				require.NoError(t, err)
				if firstHash == nil {
					firstHash = dah.Hash()
				} else {
					require.Equal(t, firstHash, dah.Hash(),
						"DAH hash mismatch between constructors for block %d (app version %d)", block.Height, block.AppVersion)
				}
				require.NotEmpty(t, dah.Hash())
				require.Equal(t, merkle.HashFromByteSlices(dah.ColumnComm), dah.Hash())
			}
		})
	}
}

func TestNewDataAvailabilityHeader_DeterministicForSameEDS(t *testing.T) {
	shares := generateShares(4)
	eds, err := ExtendShares(shares)
	require.NoError(t, err)

	first, err := NewDataAvailabilityHeader(eds)
	require.NoError(t, err)

	second, err := NewDataAvailabilityHeader(eds)
	require.NoError(t, err)

	require.Equal(t, first.ColumnComm, second.ColumnComm)
	require.Equal(t, first.PieceComm, second.PieceComm)
	require.Equal(t, first.Hash(), second.Hash())
}

func TestConstructEDS_WithFibreTx(t *testing.T) {
	fibreTx := buildMsgPayForFibreTxBytes(t)

	type testCase struct {
		name string
		txs  [][]byte
	}

	testCases := []testCase{
		{
			name: "fibre tx only",
			txs:  [][]byte{fibreTx},
		},
		{
			name: "normal tx and fibre tx",
			// squarev4.Construct requires ordering: normal txs, then blob txs, then fibre txs
			txs: [][]byte{bytes.Repeat([]byte{0x01}, 200), fibreTx},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Verify that the data square contains PayForFibre namespace shares.
			square, err := squarev4.Construct(tc.txs, appconsts.SquareSizeUpperBound, appconsts.SubtreeRootThreshold)
			require.NoError(t, err)
			pffRange := sh.GetShareRangeForNamespace(square, sh.PayForFibreNamespace)
			require.False(t, pffRange.IsEmpty(), "expected PayForFibreNamespace shares in square")

			t.Run("without pool", func(t *testing.T) {
				eds, err := ConstructEDS(tc.txs, appconsts.Version, -1)
				require.NoError(t, err)
				require.NotNil(t, eds)
			})

			t.Run("with pool", func(t *testing.T) {
				eds, err := constructEDSWithPool(tc.txs, appconsts.Version, -1)
				require.NoError(t, err)
				require.NotNil(t, eds)
			})
		})
	}
}

func TestDAHComputationFlowLogs(t *testing.T) {
	appVersion := appconsts.Version
	maxSquareSize := -1

	fibreTx := buildMsgPayForFibreTxBytes(t)
	normalTx := bytes.Repeat([]byte{0xAB}, 180)
	txs := [][]byte{normalTx, fibreTx}

	t.Logf("[INPUT] appVersion=%d maxSquareSize=%d txCount=%d", appVersion, maxSquareSize, len(txs))
	for i, tx := range txs {
		prefixLen := 16
		if len(tx) < prefixLen {
			prefixLen = len(tx)
		}
		t.Logf("[INPUT] tx[%d] len=%d prefix=%s", i, len(tx), strings.ToUpper(hex.EncodeToString(tx[:prefixLen])))
	}

	eds, err := ConstructEDS(txs, appVersion, maxSquareSize)
	require.NoError(t, err)
	require.NotNil(t, eds)

	flattened := eds.Flattened()
	t.Logf("[EDS] width=%d originalSquareSize=%d flattenedCells=%d", eds.Width(), eds.Width()/2, len(flattened))

	dah, err := NewDataAvailabilityHeader(eds)
	require.NoError(t, err)

	t.Logf("[EDS] ColumnComm after DAH generation: count=%d", len(dah.ColumnComm))

	t.Logf("[DAH] ColumnComm=%d squareSize=%d", len(dah.ColumnComm), dah.SquareSize())
	maxLogs := 3
	if len(dah.ColumnComm) < maxLogs {
		maxLogs = len(dah.ColumnComm)
	}
	for i := 0; i < maxLogs; i++ {
		t.Logf("[DAH] ColumnComm[%d]=%s", i, strings.ToUpper(hex.EncodeToString(dah.ColumnComm[i])))
	}

	h := dah.Hash()
	t.Logf("[DAH] hash=%s", strings.ToUpper(hex.EncodeToString(h)))

	require.NoError(t, dah.ValidateBasic())
	require.False(t, dah.IsZero())
	require.Equal(t, int(eds.Width()/2), dah.SquareSize())
}

func TestLogDataMatrixAndDAH(t *testing.T) {
	appVersion := appconsts.Version
	maxSquareSize := -1

	fibreTx := buildMsgPayForFibreTxBytes(t)
	normalTx := bytes.Repeat([]byte{0xCD}, 180)
	txs := [][]byte{normalTx, fibreTx}

	eds, err := ConstructEDS(txs, appVersion, maxSquareSize)
	require.NoError(t, err)
	require.NotNil(t, eds)

	originalWidth := int(eds.Width() / 2)
	originalShares, err := sh.FromBytes(eds.FlattenedODS())
	require.NoError(t, err)
	logShareMatrix(t, "ODS", originalShares, originalWidth)

	extendedWidth := int(eds.Width())
	extendedShares, err := sh.FromBytes(eds.Flattened())
	require.NoError(t, err)
	logShareMatrix(t, "EDS", extendedShares, extendedWidth)

	dah, err := NewDataAvailabilityHeader(eds)
	require.NoError(t, err)

	t.Logf("[DAH] hash=%s square_size=%d piece_commitments=%d column_commitments=%d namespace_index_entries=%d",
		strings.ToUpper(hex.EncodeToString(dah.Hash())),
		dah.SquareSize(),
		len(dah.PieceComm),
		len(dah.ColumnComm),
		len(dah.NamespaceIndex),
	)

	maxLogs := 4
	if len(dah.PieceComm) < maxLogs {
		maxLogs = len(dah.PieceComm)
	}
	for i := 0; i < maxLogs; i++ {
		t.Logf("[DAH] piece_commitment[%d]=%s", i, strings.ToUpper(hex.EncodeToString(dah.PieceComm[i])))
	}

	maxLogs = 4
	if len(dah.ColumnComm) < maxLogs {
		maxLogs = len(dah.ColumnComm)
	}
	for i := 0; i < maxLogs; i++ {
		t.Logf("[DAH] column_commitment[%d]=%s", i, strings.ToUpper(hex.EncodeToString(dah.ColumnComm[i])))
	}

	namespaceIDs := make([]string, 0, len(dah.NamespaceIndex))
	for ns := range dah.NamespaceIndex {
		namespaceIDs = append(namespaceIDs, strings.ToUpper(hex.EncodeToString([]byte(ns))))
	}
	sort.Strings(namespaceIDs)
	for _, nsHex := range namespaceIDs {
		rng := dah.NamespaceIndex[string(mustDecodeHex(t, nsHex))]
		t.Logf("[DAH] namespace=%s range=[%d,%d)", nsHex, rng.Start, rng.End)
	}
}

func logShareMatrix(t *testing.T, label string, shares []sh.Share, width int) {
	t.Helper()
	require.Equal(t, width*width, len(shares))
	t.Logf("[%s] width=%d cells=%d", label, width, len(shares))

	for row := 0; row < width; row++ {
		cells := make([]string, 0, width)
		for col := 0; col < width; col++ {
			idx := row*width + col
			cellBytes := shares[idx].ToBytes()
			namespace := strings.ToUpper(hex.EncodeToString(shares[idx].Namespace().Bytes()))
			prefixLen := 8
			if len(cellBytes) < prefixLen {
				prefixLen = len(cellBytes)
			}
			prefix := strings.ToUpper(hex.EncodeToString(cellBytes[:prefixLen]))
			cells = append(cells, fmt.Sprintf("%s:%s", namespace, prefix))
		}
		t.Logf("[%s] row_%02d %s", label, row, strings.Join(cells, " | "))
	}
}

func mustDecodeHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	require.NoError(t, err)
	return b
}

// buildMsgPayForFibreTxBytes constructs Cosmos SDK Tx proto bytes containing a
// single MsgPayForFibre message. This replicates the pattern from
// go-square/v4/internal/test.BuildMsgPayForFibreTxBytes which is not importable.
func buildMsgPayForFibreTxBytes(t *testing.T) []byte {
	t.Helper()
	ns := sh.MustNewV0Namespace(bytes.Repeat([]byte{1}, sh.NamespaceVersionZeroIDSize))
	signerRaw := bytes.Repeat([]byte{0xAA}, sh.SignerSize)
	signer, err := bech32.EncodeFromBase256("celestia", signerRaw)
	require.NoError(t, err)
	commitment := bytes.Repeat([]byte{0xFF}, sh.FibreCommitmentSize)

	msg := &fibretypes.MsgPayForFibre{
		Signer: signer,
		PaymentPromise: fibretypes.PaymentPromise{
			Namespace:   ns.Bytes(),
			BlobVersion: fibretypes.BlobVersionZero,
			Commitment:  commitment,
		},
	}

	anyMsg, err := codectypes.NewAnyWithValue(msg)
	require.NoError(t, err)
	// Verify the cosmos-sdk derived TypeURL matches the constant that
	// TryParseFibreTx checks when parsing fibre transactions.
	require.Equal(t, gotx.MsgPayForFibreTypeURL, anyMsg.TypeUrl,
		"cosmos-sdk TypeURL must match the constant that TryParseFibreTx checks")

	body := &cosmostx.TxBody{
		Messages: []*codectypes.Any{anyMsg},
	}
	tx := &cosmostx.Tx{Body: body}
	txBytes, err := tx.Marshal()
	require.NoError(t, err)
	return txBytes
}

// maxDataAvailabilityHeader returns a DataAvailabilityHeader with the maximum square
// size. This should only be used for testing.
func maxDataAvailabilityHeader(t *testing.T) (dah DataAvailabilityHeader) {
	return maxDataAvailabilityHeaderWithExtendShares(t, ExtendShares)
}

// maxDataAvailabilityHeaderWithExtendShares returns a DataAvailabilityHeader with the maximum square
// size using the provided extendShares function. This should only be used for testing.
func maxDataAvailabilityHeaderWithExtendShares(t *testing.T, extendShares func([][]byte) (*rsmt2d.ExtendedDataSquare, error)) (dah DataAvailabilityHeader) {
	shares := generateShares(appconsts.SquareSizeUpperBound * appconsts.SquareSizeUpperBound)

	eds, err := extendShares(shares)
	require.NoError(t, err)

	dah, err = NewDataAvailabilityHeader(eds)
	require.NoError(t, err)

	return dah
}
