package cln

import (
	"crypto/sha256"
	"encoding/binary"

	"github.com/btcsuite/btcd/btcec/v2"
	"golang.org/x/crypto/hkdf"
)

var (
	InfoPeerSeed   = []byte("peer seed")
	InfoPerPeer    = []byte("per-peer seed")
	InfoCLightning = []byte("c-lightning")
)

// FundingKey derives a CLN channel funding key for the given peer and channel
// number (incrementing database index).
func FundingKey(hsmSecret [32]byte, peerPubKey *btcec.PublicKey,
	channelNum uint64) (*btcec.PublicKey, error) {

	channelBase, err := HkdfSha256(hsmSecret[:], nil, InfoPeerSeed)
	if err != nil {
		return nil, err
	}

	peerAndChannel := make([]byte, 33+8)
	copy(peerAndChannel[:33], peerPubKey.SerializeCompressed())
	binary.LittleEndian.PutUint64(peerAndChannel[33:], channelNum)

	channelSeed, err := HkdfSha256(
		channelBase[:], peerAndChannel[:], InfoPerPeer,
	)
	if err != nil {
		return nil, err
	}

	fundingKey, err := HkdfSha256(channelSeed[:], nil, InfoCLightning)
	if err != nil {
		return nil, err
	}

	_, pubKey := btcec.PrivKeyFromBytes(fundingKey[:])
	return pubKey, nil
}

// HkdfSha256 derives a 32-byte key from the given input key material, salt, and
// info using the HKDF-SHA256 key derivation function.
func HkdfSha256(key, salt, info []byte) ([32]byte, error) {
	expander := hkdf.New(sha256.New, key, salt, info)
	var outputKey [32]byte

	_, err := expander.Read(outputKey[:])
	if err != nil {
		return [32]byte{}, err
	}

	return outputKey, nil
}
