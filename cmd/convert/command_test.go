package convert

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestConvertKeyFormat(t *testing.T) {
	// Test key
	testKey := "000bbc3112bd249176b12e0f40ecaa1ec2c6b89e8b6d9cd244e609693a891b7b"

	// Create temporary directory for test files
	tmpDir := t.TempDir()

	tests := []struct {
		name         string
		key          string
		format       string
		showExtra    bool
		outputFile   string
		password     string
		validateFunc func(t *testing.T, data []byte)
	}{
		{
			name:       "libp2p format",
			key:        testKey,
			format:     "libp2p",
			showExtra:  true,
			outputFile: filepath.Join(tmpDir, "test.libp2p.json"),
			validateFunc: func(t *testing.T, data []byte) {
				var output LibP2PKeyOutput
				err := json.Unmarshal(data, &output)
				require.NoError(t, err)
				assert.Equal(t, testKey, output.PrivateKey)
				assert.NotEmpty(t, output.ID)
				assert.NotNil(t, output.Extra)
				assert.Equal(t, "Secp256k1", output.Extra.Type)
				assert.Equal(t, "16Uiu2HAm9hPUmSZbyoRjQvF7T1MGh5XNYPNPcSZsrHtDBpib5PW2", output.ID)
				assert.Equal(t, "000bbc3112bd249176b12e0f40ecaa1ec2c6b89e8b6d9cd244e609693a891b7b", output.PubKey)
			},
		},
		{
			name:       "binary format",
			key:        testKey,
			format:     "binary",
			outputFile: filepath.Join(tmpDir, "test.bin"),
			validateFunc: func(t *testing.T, data []byte) {
				assert.Equal(t, testKey, hex.EncodeToString(data))
			},
		},
		{
			name:       "keystore format",
			key:        testKey,
			format:     "keystore",
			outputFile: filepath.Join(tmpDir, "test.keystore.json"),
			password:   "testpassword",
			validateFunc: func(t *testing.T, data []byte) {
				var output KeystoreOutput
				err := json.Unmarshal(data, &output)
				require.NoError(t, err)
				assert.Equal(t, 1, output.Version)
				assert.NotEmpty(t, output.UUID)
				assert.Equal(t, "scrypt", output.Crypto.KDF.Function)
				assert.Equal(t, "aes-128-ctr", output.Crypto.Cipher.Function)
				assert.Equal(t, "sha256", output.Crypto.Checksum.Function)
				assert.Equal(t, "0802122102d40a40b6bdb6a47aa498e93749a934a6a6c8463da47f437ab3587cc89c8cf3cb", output.Pubkey)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Set command flags
			ecdsaKey = tt.key
			outputFormat = tt.format
			showExtra = tt.showExtra
			outputFile = tt.outputFile
			keystorePassword = tt.password

			// Run the command
			err := runConvertKeyFormat(nil, nil)
			require.NoError(t, err)

			// Read the output file
			data, err := os.ReadFile(tt.outputFile)
			require.NoError(t, err)

			// Validate the output
			tt.validateFunc(t, data)
		})
	}
}
