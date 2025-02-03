package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/btcsuite/btcd/btcutil/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	"github.com/stretchr/testify/require"
)

var (
	oldNodeRootKey = "tprv8ZgxMBicQKsPew1XiTmCmnZNSqTpy1eqSKg2ZjcFojcFtSM" +
		"bB5HUxQA5LyCfLgBB9aqWPqtPNLeMo3CR6uMASfbyQiUfTcAN6ECvE9F9qUy"
)

func TestAncientKeyDerivation(t *testing.T) {
	chainParams = &chaincfg.RegressionNetParams

	jsonBytes, err := os.ReadFile("./sweepremoteclosed_ancient.json")
	require.NoError(t, err)

	var ancients []ancientChannel
	err = json.Unmarshal(jsonBytes, &ancients)
	require.NoError(t, err)

	oldRootKey, err := hdkeychain.NewKeyFromString(oldNodeRootKey)
	require.NoError(t, err)

	oldChans, err := findAncientChannels(ancients, 5, oldRootKey)
	require.NoError(t, err)

	require.NotEmpty(t, oldChans)
}

func unhex(t *testing.T, str string) []byte {
	str = strings.ReplaceAll(str, " ", "")
	b, err := hex.DecodeString(str)
	require.NoError(t, err)
	return b
}

func hash(t *testing.T, str string) chainhash.Hash {
	h, err := chainhash.NewHashFromStr(str)
	require.NoError(t, err)
	return *h
}

func TestCreateTx(t *testing.T) {
	tx := &wire.MsgTx{
		Version: 2,
		TxIn: []*wire.TxIn{{
			PreviousOutPoint: wire.OutPoint{
				Hash: hash(t, "7fc0278c11f2ac4773caa3dcea56d"+
					"2c7883b124c06588651216255e0f9c9a24f"),
				Index: 0,
			},
			Sequence: 2157913601,
			Witness: [][]byte{
				nil,
				unhex(t, "30 45 02 21 00 c0 88 6a 4c f4 77 24"+
					" 68 45 50 c1 ec e8 94 29 fe bc c5 a3"+
					" 0c f7 1a 7b a9 37 28 14 92 90 04 5d"+
					" aa 02 20 2c 52 69 32 a1 da a7 84 58"+
					" 95 b4 84 f7 46 1c 44 1e f7 b5 3c 59"+
					" f3 9e a2 6a b0 5a b3 a6 be 53 0d 01"),
				unhex(t, "30 44 02 20 3b 00 4d 82 fe c6 3c fe"+
					" ba 09 73 66 59 9b 25 c7 21 da 48 06"+
					" 2c 86 12 09 9e 1b 15 e0 f3 49 a9 6c"+
					" 02 20 1f 77 34 ce 2f 49 db f1 44 00"+
					" 0b 9a 41 94 68 2a 86 b2 45 a9 68 74"+
					" bf eb 5d 1a ce 83 ed 2a 46 06 01"),
				unhex(t, "52 21 02 34 99 0e f6 80 ff 3b e9 1e"+
					" 86 2c 1b 5f 97 3c 7d 21 ef 3e a1 e4"+
					" e9 40 f3 cb bb e3 dc 94 1b d3 61 21"+
					" 02 ea 1f 0d f7 3d 6a 3a 8e c9 ae 81"+
					" c7 5f 01 4b 2b b6 7c 17 36 e0 9b 70"+
					" c7 4e a6 58 5f 55 9b 40 c7 52 ae"),
			},
		}},
		TxOut: []*wire.TxOut{{
			Value: 15000,
			PkScript: unhex(t, "00 14 ac 56 01 6d 51 e9 fe d2 81 "+
				"a1 48 7c 9c f1 74 26 14 f1 af 2e"),
		}, {
			Value: 4975950,
			PkScript: unhex(t, "00 20 d2 38 19 91 40 3a b2 aa 5a "+
				"79 27 5a 29 d5 0e cf aa 53 4c ca 00 49 f9 "+
				"cf fd ca 07 7c 17 4f af f1"),
		}},
		LockTime: 553223869,
	}
	t.Logf("%v", tx.TxHash())

	var buf bytes.Buffer
	err := tx.Serialize(&buf)
	require.NoError(t, err)
	t.Logf("%x", buf.Bytes())
}
