package main

import (
	"encoding/hex"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/stretchr/testify/require"
)

func TestMatchScript(t *testing.T) {
	testCases := []struct {
		key1   string
		key2   string
		addr   string
		params *chaincfg.Params
	}{{
		key1:   "0201943d78d61c8ad50ba57164830f536c156d8d89d979448bef3e67f564ea0ab6",
		key2:   "038b88de18064024e9da4dfc9c804283b3077a265dcd73ad3615b50badcbdebd5b",
		addr:   "bc1qp5jnhnavt32fjwhnf5ttpvvym7e0syp79q5l9skz545q62d8u2uq05ul63",
		params: &chaincfg.MainNetParams,
	}, {
		key1:   "03585d8e760bd0925da67d9c22a69dcad9f51f90a39f9a681971268555975ea30d",
		key2:   "0326a2171c97673cc8cd7a04a043f0224c59591fc8c9de320a48f7c9b68ab0ae2b",
		addr:   "bcrt1qhcn39q6jc0krkh9va230y2z6q96zadt8fhxw3erv92fzlrw83cyq40nwek",
		params: &chaincfg.RegressionNetParams,
	}}

	for _, tc := range testCases {
		key1Bytes, err := hex.DecodeString(tc.key1)
		require.NoError(t, err)
		key1, err := btcec.ParsePubKey(key1Bytes)
		require.NoError(t, err)

		key2Bytes, err := hex.DecodeString(tc.key2)
		require.NoError(t, err)
		key2, err := btcec.ParsePubKey(key2Bytes)
		require.NoError(t, err)

		ok, _, err := matchScript(tc.addr, key1, key2, tc.params)
		require.NoError(t, err)
		require.True(t, ok)
	}
}
