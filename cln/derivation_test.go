package cln

import (
	"encoding/hex"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/stretchr/testify/require"
)

var (
	hsmSecret = [32]byte{
		0x3f, 0x0a, 0x06, 0xc6, 0x38, 0x5b, 0x74, 0x93,
		0xf7, 0x5a, 0xa0, 0x08, 0x9f, 0x31, 0x6a, 0x13,
		0xbf, 0x72, 0xbe, 0xb4, 0x30, 0xe5, 0x9e, 0x71,
		0xb5, 0xac, 0x5a, 0x73, 0x58, 0x1a, 0x62, 0x70,
	}
	nodeKeyBytes, _ = hex.DecodeString(
		"035149629152c1bee83f1e148a51400b5f24bf3e2ca53384dd801418446e" +
			"1f53fe",
	)

	peerPubKeyBytes, _ = hex.DecodeString(
		"02678187ca43e6a6f62f9185be98a933bf485313061e6a05578bbd83c54e" +
			"88d460",
	)
	peerPubKey, _ = btcec.ParsePubKey(peerPubKeyBytes)

	expectedFundingKeyBytes, _ = hex.DecodeString(
		"0326a2171c97673cc8cd7a04a043f0224c59591fc8c9de320a48f7c9b68a" +
			"b0ae2b",
	)
)

func TestNodeKey(t *testing.T) {
	nodeKey, err := NodeKey(hsmSecret)
	require.NoError(t, err)

	require.Equal(t, nodeKeyBytes, nodeKey.SerializeCompressed())
}

func TestFundingKey(t *testing.T) {
	fundingKey, err := FundingKey(hsmSecret, peerPubKey, 1)
	require.NoError(t, err)

	require.Equal(
		t, expectedFundingKeyBytes, fundingKey.SerializeCompressed(),
	)
}
