package scbforceclose

import (
	"bytes"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"

	"github.com/btcsuite/btcd/btcutil/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/txscript"
	"github.com/lightninglabs/chantools/lnd"
	"github.com/lightningnetwork/lnd/aezeed"
	"github.com/lightningnetwork/lnd/chanbackup"
	"github.com/lightningnetwork/lnd/input"
	"github.com/stretchr/testify/require"
)

//go:embed testdata/channel_backups.json
var channelBackupsJSON []byte

// TestSignCloseTx tests that SignCloseTx produces valid transactions.
func TestSignCloseTx(t *testing.T) {
	// Load prepared channel backups with seeds and passwords.
	type TestCase struct {
		Name          string `json:"name"`
		RootKey       string `json:"rootkey"`
		Password      string `json:"password"`
		Mnemonic      string `json:"mnemonic"`
		Single        bool   `json:"single"`
		ChannelBackup string `json:"channel_backup"`
		PkScript      string `json:"pk_script"`
		AmountSats    int64  `json:"amount_sats"`
	}

	var testdata struct {
		Cases []TestCase `json:"cases"`
	}
	require.NoError(t, json.Unmarshal(channelBackupsJSON, &testdata))

	chainParams := &chaincfg.RegressionNetParams

	for _, tc := range testdata.Cases {
		t.Run(tc.Name, func(t *testing.T) {
			var extendedKey *hdkeychain.ExtendedKey
			if tc.RootKey != "" {
				// Parse root key.
				var err error
				extendedKey, err = hdkeychain.NewKeyFromString(
					tc.RootKey,
				)
				require.NoError(t, err)
			} else {
				// Generate root key from seed and password.
				words := strings.Split(tc.Mnemonic, " ")
				require.Len(t, words, 24)
				var mnemonic aezeed.Mnemonic
				copy(mnemonic[:], words)
				cipherSeed, err := mnemonic.ToCipherSeed(
					[]byte(tc.Password),
				)
				require.NoError(t, err)
				extendedKey, err = hdkeychain.NewMaster(
					cipherSeed.Entropy[:], chainParams,
				)
				require.NoError(t, err)
			}

			// Make key ring and signer.
			keyRing := &lnd.HDKeyRing{
				ExtendedKey: extendedKey,
				ChainParams: chainParams,
			}

			signer := &lnd.Signer{
				ExtendedKey: extendedKey,
				ChainParams: chainParams,
			}
			musigSessionManager := input.NewMusigSessionManager(
				signer.FetchPrivateKey,
			)
			signer.MusigSessionManager = musigSessionManager

			// Unpack channel.backup.
			backup, err := hex.DecodeString(
				tc.ChannelBackup,
			)
			require.NoError(t, err)
			r := bytes.NewReader(backup)

			var s chanbackup.Single
			if tc.Single {
				err := s.UnpackFromReader(r, keyRing)
				require.NoError(t, err)
			} else {
				var m chanbackup.Multi
				err := m.UnpackFromReader(r, keyRing)
				require.NoError(t, err)

				// Extract a single channel backup from
				// multi backup.
				require.Len(t, m.StaticBackups, 1)
				s = m.StaticBackups[0]
			}

			// Sign force close transaction.
			sweepTx, err := SignCloseTx(
				s, keyRing, signer, signer,
			)
			require.NoError(t, err)

			// Check if the transaction is valid.
			pkScript, err := hex.DecodeString(tc.PkScript)
			require.NoError(t, err)
			fetcher := txscript.NewCannedPrevOutputFetcher(
				pkScript, tc.AmountSats,
			)

			sigHashes := txscript.NewTxSigHashes(sweepTx, fetcher)

			vm, err := txscript.NewEngine(
				pkScript, sweepTx, 0,
				txscript.StandardVerifyFlags,
				nil, sigHashes, tc.AmountSats, fetcher,
			)
			require.NoError(t, err)

			require.NoError(t, vm.Execute())
		})
	}
}
