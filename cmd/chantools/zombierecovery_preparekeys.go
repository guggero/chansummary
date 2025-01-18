package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/wire"
	"github.com/lightninglabs/chantools/cln"
	"github.com/lightninglabs/chantools/lnd"
	"github.com/spf13/cobra"
)

const (
	numMultisigKeys = 2500
)

type zombieRecoveryPrepareKeysCommand struct {
	MatchFile  string
	PayoutAddr string

	NumKeys uint32

	HsmSecret string

	rootKey *rootKey
	cmd     *cobra.Command
}

func newZombieRecoveryPrepareKeysCommand() *cobra.Command {
	cc := &zombieRecoveryPrepareKeysCommand{}
	cc.cmd = &cobra.Command{
		Use:   "preparekeys",
		Short: "[1/3] Prepare all public keys for a recovery attempt",
		Long: `Takes a match file, validates it against the seed and 
then adds the first 2500 multisig pubkeys to it.
This must be run by both parties of a channel for a successful recovery. The
next step (makeoffer) takes two such key enriched files and tries to find the
correct ones for the matched channels.`,
		Example: `chantools zombierecovery preparekeys \
	--match_file match-xxxx-xx-xx-<pubkey1>-<pubkey2>.json \
	--payout_addr bc1q...`,
		RunE: cc.Execute,
	}

	cc.cmd.Flags().StringVar(
		&cc.MatchFile, "match_file", "", "the match JSON file that "+
			"was sent to both nodes by the match maker",
	)
	cc.cmd.Flags().StringVar(
		&cc.PayoutAddr, "payout_addr", "", "the address where this "+
			"node's rescued funds should be sent to, must be a "+
			"P2WPKH (native SegWit) or P2TR (Taproot) address",
	)
	cc.cmd.Flags().Uint32Var(
		&cc.NumKeys, "num_keys", numMultisigKeys, "the number of "+
			"multisig keys to derive",
	)
	cc.cmd.Flags().StringVar(
		&cc.HsmSecret, "hsm_secret", "", "the hex encoded HSM secret "+
			"to use for deriving the multisig keys for a CLN "+
			"node; obtain by running 'xxd -p -c32 "+
			"~/.lightning/bitcoin/hsm_secret'",
	)

	cc.rootKey = newRootKey(cc.cmd, "deriving the multisig keys")

	return cc.cmd
}

func (c *zombieRecoveryPrepareKeysCommand) Execute(_ *cobra.Command,
	_ []string) error {

	err := lnd.CheckAddress(
		c.PayoutAddr, chainParams, false, "payout", lnd.AddrTypeP2WKH,
		lnd.AddrTypeP2TR,
	)
	if err != nil {
		return errors.New("invalid payout address, must be P2WPKH or " +
			"P2TR")
	}

	matchFileBytes, err := os.ReadFile(c.MatchFile)
	if err != nil {
		return fmt.Errorf("error reading match file %s: %w",
			c.MatchFile, err)
	}

	var match match
	if err := json.Unmarshal(matchFileBytes, &match); err != nil {
		return fmt.Errorf("error decoding match file %s: %w",
			c.MatchFile, err)
	}

	// Make sure the match file was filled correctly.
	if match.Node1 == nil || match.Node2 == nil {
		return errors.New("invalid match file, node info missing")
	}

	// Derive the keys for the node type, depending on the input flags.
	var pubKeyStr string
	switch {
	case c.HsmSecret != "":
		pubKeyStr, err = c.clnDeriveKeys(&match)
	default:
		pubKeyStr, err = c.lndDeriveKeys(&match)
	}
	if err != nil {
		return err
	}

	// Write the result back into a new file.
	matchBytes, err := json.MarshalIndent(match, "", " ")
	if err != nil {
		return err
	}

	fileName := fmt.Sprintf("results/preparedkeys-%s-%s.json",
		time.Now().Format("2006-01-02"), pubKeyStr)
	log.Infof("Writing result to %s", fileName)
	return os.WriteFile(fileName, matchBytes, 0644)
}

func (c *zombieRecoveryPrepareKeysCommand) lndDeriveKeys(match *match) (string,
	error) {

	extendedKey, err := c.rootKey.read()
	if err != nil {
		return "", fmt.Errorf("error reading root key: %w", err)
	}

	_, pubKey, _, err := lnd.DeriveKey(
		extendedKey, lnd.IdentityPath(chainParams), chainParams,
	)
	if err != nil {
		return "", fmt.Errorf("error deriving identity pubkey: %w", err)
	}

	pubKeyStr := hex.EncodeToString(pubKey.SerializeCompressed())
	var nodeInfo *nodeInfo
	switch {
	case match.Node1.PubKey != pubKeyStr && match.Node2.PubKey != pubKeyStr:
		return "", fmt.Errorf("derived pubkey %s from seed but that "+
			"key was not found in the match file %s", pubKeyStr,
			c.MatchFile)

	case match.Node1.PubKey == pubKeyStr:
		nodeInfo = match.Node1

	default:
		nodeInfo = match.Node2
	}

	// If there are any Simple Taproot channels, we need to generate some
	// randomness and nonces from that randomness for each channel.
	for idx := range match.Channels {
		matchChannel := match.Channels[idx]
		addr, err := lnd.ParseAddress(matchChannel.Address, chainParams)
		if err != nil {
			return "", fmt.Errorf("error parsing channel funding "+
				"address '%s': %w", matchChannel.Address, err)
		}

		_, isP2TR := addr.(*btcutil.AddressTaproot)
		if isP2TR {
			chanPoint, err := wire.NewOutPointFromString(
				matchChannel.ChanPoint,
			)
			if err != nil {
				return "", fmt.Errorf("error parsing channel "+
					"point %s: %w", matchChannel.ChanPoint,
					err)
			}

			var randomness [32]byte
			if _, err := rand.Read(randomness[:]); err != nil {
				return "", err
			}

			nonces, err := lnd.GenerateMuSig2Nonces(
				extendedKey, randomness, chanPoint, chainParams,
				nil,
			)
			if err != nil {
				return "", fmt.Errorf("error generating "+
					"MuSig2 nonces: %w", err)
			}

			matchChannel.MuSig2NonceRandomness = hex.EncodeToString(
				randomness[:],
			)
			matchChannel.MuSig2Nonces = hex.EncodeToString(
				nonces.PubNonce[:],
			)
		}
	}

	// Derive all 2500 keys now, this might take a while.
	for index := range c.NumKeys {
		_, pubKey, _, err := lnd.DeriveKey(
			extendedKey, lnd.MultisigPath(chainParams, int(index)),
			chainParams,
		)
		if err != nil {
			return "", fmt.Errorf("error deriving multisig "+
				"pubkey: %w", err)
		}

		nodeInfo.MultisigKeys = append(
			nodeInfo.MultisigKeys,
			hex.EncodeToString(pubKey.SerializeCompressed()),
		)
	}
	nodeInfo.PayoutAddr = c.PayoutAddr

	return pubKeyStr, nil
}

func (c *zombieRecoveryPrepareKeysCommand) clnDeriveKeys(match *match) (string,
	error) {

	secretBytes, err := hex.DecodeString(c.HsmSecret)
	if err != nil {
		return "", fmt.Errorf("error decoding HSM secret: %w", err)
	}

	var hsmSecret [32]byte
	copy(hsmSecret[:], secretBytes)

	nodePubKey, err := cln.NodeKey(hsmSecret)
	if err != nil {
		return "", fmt.Errorf("error deriving node pubkey: %w", err)
	}

	pubKeyStr := hex.EncodeToString(nodePubKey.SerializeCompressed())
	var ourNodeInfo, theirNodeInfo *nodeInfo
	switch {
	case match.Node1.PubKey != pubKeyStr && match.Node2.PubKey != pubKeyStr:
		return "", fmt.Errorf("derived pubkey %s from seed but that "+
			"key was not found in the match file %s", pubKeyStr,
			c.MatchFile)

	case match.Node1.PubKey == pubKeyStr:
		ourNodeInfo = match.Node1
		theirNodeInfo = match.Node2

	default:
		ourNodeInfo = match.Node2
		theirNodeInfo = match.Node1
	}

	theirNodeKeyBytes, err := hex.DecodeString(theirNodeInfo.PubKey)
	if err != nil {
		return "", fmt.Errorf("error decoding peer pubkey: %w", err)
	}
	theirNodeKey, err := btcec.ParsePubKey(theirNodeKeyBytes)
	if err != nil {
		return "", fmt.Errorf("error parsing peer pubkey: %w", err)
	}

	// Derive all 2500 keys now, this might take a while.
	for index := range c.NumKeys {
		pubKey, err := cln.FundingKey(
			hsmSecret, theirNodeKey, uint64(index),
		)
		if err != nil {
			return "", fmt.Errorf("error deriving multisig "+
				"pubkey: %w", err)
		}

		ourNodeInfo.MultisigKeys = append(
			ourNodeInfo.MultisigKeys,
			hex.EncodeToString(pubKey.SerializeCompressed()),
		)
	}
	ourNodeInfo.PayoutAddr = c.PayoutAddr

	return pubKeyStr, nil
}
