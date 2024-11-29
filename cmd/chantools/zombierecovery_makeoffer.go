package main

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcec/v2/schnorr/musig2"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/btcutil/hdkeychain"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcwallet/wallet"
	"github.com/lightninglabs/chantools/lnd"
	"github.com/lightningnetwork/lnd/fn"
	"github.com/lightningnetwork/lnd/input"
	"github.com/lightningnetwork/lnd/keychain"
	"github.com/lightningnetwork/lnd/lnwallet"
	"github.com/lightningnetwork/lnd/lnwallet/chainfee"
	"github.com/spf13/cobra"
)

type zombieRecoveryMakeOfferCommand struct {
	Node1   string
	Node2   string
	FeeRate uint32

	MatchOnly bool

	rootKey *rootKey
	cmd     *cobra.Command
}

func newZombieRecoveryMakeOfferCommand() *cobra.Command {
	cc := &zombieRecoveryMakeOfferCommand{}
	cc.cmd = &cobra.Command{
		Use: "makeoffer",
		Short: "[2/3] Make an offer on how to split the funds to " +
			"recover",
		Long: `After both parties have prepared their keys with the
'preparekeys' command and have  exchanged the files generated from that step,
one party has to create an offer on how to split the funds that are in the
channels to be rescued.
If the other party agrees with the offer, they can sign and publish the offer
with the 'signoffer' command. If the other party does not agree, they can create
a counter offer.`,
		Example: `chantools zombierecovery makeoffer \
	--node1_keys preparedkeys-xxxx-xx-xx-<pubkey1>.json \
	--node2_keys preparedkeys-xxxx-xx-xx-<pubkey2>.json \
	--feerate 15`,
		RunE: cc.Execute,
	}

	cc.cmd.Flags().StringVar(
		&cc.Node1, "node1_keys", "", "the JSON file generated in the"+
			"previous step ('preparekeys') command of node 1",
	)
	cc.cmd.Flags().StringVar(
		&cc.Node2, "node2_keys", "", "the JSON file generated in the"+
			"previous step ('preparekeys') command of node 2",
	)
	cc.cmd.Flags().Uint32Var(
		&cc.FeeRate, "feerate", defaultFeeSatPerVByte, "fee rate to "+
			"use for the sweep transaction in sat/vByte",
	)
	cc.cmd.Flags().BoolVar(
		&cc.MatchOnly, "matchonly", false, "only match the keys, "+
			"don't create an offer",
	)

	cc.rootKey = newRootKey(cc.cmd, "signing the offer")

	return cc.cmd
}

func (c *zombieRecoveryMakeOfferCommand) Execute(_ *cobra.Command,
	_ []string) error {

	extendedKey, err := c.rootKey.read()
	if err != nil {
		return fmt.Errorf("error reading root key: %w", err)
	}

	if c.FeeRate == 0 {
		c.FeeRate = defaultFeeSatPerVByte
	}

	node1Bytes, err := os.ReadFile(c.Node1)
	if err != nil {
		return fmt.Errorf("error reading node1 key file %s: %w",
			c.Node1, err)
	}
	node2Bytes, err := os.ReadFile(c.Node2)
	if err != nil {
		return fmt.Errorf("error reading node2 key file %s: %w",
			c.Node2, err)
	}
	keys1, keys2 := &match{}, &match{}
	decoder := json.NewDecoder(bytes.NewReader(node1Bytes))
	if err := decoder.Decode(&keys1); err != nil {
		return fmt.Errorf("error decoding node1 key file %s: %w",
			c.Node1, err)
	}
	decoder = json.NewDecoder(bytes.NewReader(node2Bytes))
	if err := decoder.Decode(&keys2); err != nil {
		return fmt.Errorf("error decoding node2 key file %s: %w",
			c.Node2, err)
	}

	// Make sure the key files were filled correctly.
	if keys1.Node1 == nil || keys1.Node2 == nil {
		return errors.New("invalid node1 file, node info missing")
	}
	if keys2.Node1 == nil || keys2.Node2 == nil {
		return errors.New("invalid node2 file, node info missing")
	}
	if keys1.Node1.PubKey != keys2.Node1.PubKey {
		return errors.New("invalid files, node 1 pubkey doesn't match")
	}
	if keys1.Node2.PubKey != keys2.Node2.PubKey {
		return errors.New("invalid files, node 2 pubkey doesn't match")
	}
	if len(keys1.Node1.MultisigKeys) == 0 &&
		len(keys1.Node2.MultisigKeys) == 0 {

		return errors.New("invalid node1 file, missing multisig keys")
	}
	if len(keys2.Node1.MultisigKeys) == 0 &&
		len(keys2.Node2.MultisigKeys) == 0 {

		return errors.New("invalid node2 file, missing multisig keys")
	}
	if len(keys1.Node1.MultisigKeys) == len(keys2.Node1.MultisigKeys) {
		return errors.New("invalid files, channel info incorrect")
	}
	if len(keys1.Node2.MultisigKeys) == len(keys2.Node2.MultisigKeys) {
		return errors.New("invalid files, channel info incorrect")
	}
	if len(keys1.Channels) != len(keys2.Channels) {
		return errors.New("invalid files, channels don't match")
	}
	for idx, node1Channel := range keys1.Channels {
		if keys2.Channels[idx].ChanPoint != node1Channel.ChanPoint {
			return errors.New("invalid files, channels don't match")
		}

		if keys2.Channels[idx].Address != node1Channel.Address {
			return errors.New("invalid files, channels don't match")
		}

		if keys2.Channels[idx].Address == "" ||
			node1Channel.Address == "" {

			return errors.New("invalid files, channel address " +
				"missing")
		}

		if len(keys2.Channels[idx].MuSig2Nonces) !=
			len(node1Channel.MuSig2Nonces) {

			return errors.New("invalid files, MuSig2 nonce " +
				"lengths don't match")
		}

		if len(keys2.Channels[idx].MuSig2NonceRandomness) !=
			len(node1Channel.MuSig2NonceRandomness) {

			return errors.New("invalid files, MuSig2 randomness " +
				"lengths don't match")
		}
	}

	// If we're only matching, we can stop here.
	if c.MatchOnly {
		ourPubKeys, err := parseKeys(keys1.Node1.MultisigKeys)
		if err != nil {
			return fmt.Errorf("error parsing their keys: %w", err)
		}

		theirPubKeys, err := parseKeys(keys2.Node2.MultisigKeys)
		if err != nil {
			return fmt.Errorf("error parsing our keys: %w", err)
		}
		return matchKeys(
			keys1.Channels, ourPubKeys, theirPubKeys, chainParams,
		)
	}

	// Make sure one of the nodes is ours.
	_, pubKey, _, err := lnd.DeriveKey(
		extendedKey, lnd.IdentityPath(chainParams), chainParams,
	)
	if err != nil {
		return fmt.Errorf("error deriving identity pubkey: %w", err)
	}

	pubKeyStr := hex.EncodeToString(pubKey.SerializeCompressed())
	if keys1.Node1.PubKey != pubKeyStr && keys1.Node2.PubKey != pubKeyStr {
		return fmt.Errorf("derived pubkey %s from seed but that key "+
			"was not found in the match files", pubKeyStr)
	}

	// Pick the correct list of keys. There are 4 possibilities, given 2
	// files with 2 node slots each.
	var (
		ourKeys         []string
		ourPayoutAddr   string
		ourChannels     []*channel
		theirKeys       []string
		theirPayoutAddr string
		theirChannels   []*channel
	)
	if keys1.Node1.PubKey == pubKeyStr && len(keys1.Node1.MultisigKeys) > 0 {
		ourKeys = keys1.Node1.MultisigKeys
		ourPayoutAddr = keys1.Node1.PayoutAddr
		ourChannels = keys1.Channels
		theirKeys = keys2.Node2.MultisigKeys
		theirPayoutAddr = keys2.Node2.PayoutAddr
		theirChannels = keys2.Channels
	}
	if keys1.Node2.PubKey == pubKeyStr && len(keys1.Node2.MultisigKeys) > 0 {
		ourKeys = keys1.Node2.MultisigKeys
		ourPayoutAddr = keys1.Node2.PayoutAddr
		ourChannels = keys1.Channels
		theirKeys = keys2.Node1.MultisigKeys
		theirPayoutAddr = keys2.Node1.PayoutAddr
		theirChannels = keys2.Channels
	}
	if keys2.Node1.PubKey == pubKeyStr && len(keys2.Node1.MultisigKeys) > 0 {
		ourKeys = keys2.Node1.MultisigKeys
		ourPayoutAddr = keys2.Node1.PayoutAddr
		ourChannels = keys2.Channels
		theirKeys = keys1.Node2.MultisigKeys
		theirPayoutAddr = keys1.Node2.PayoutAddr
		theirChannels = keys1.Channels
	}
	if keys2.Node2.PubKey == pubKeyStr && len(keys2.Node2.MultisigKeys) > 0 {
		ourKeys = keys2.Node2.MultisigKeys
		ourPayoutAddr = keys2.Node2.PayoutAddr
		ourChannels = keys2.Channels
		theirKeys = keys1.Node1.MultisigKeys
		theirPayoutAddr = keys1.Node1.PayoutAddr
		theirChannels = keys1.Channels
	}
	if len(ourKeys) == 0 || len(theirKeys) == 0 {
		return errors.New("couldn't find necessary keys")
	}
	if ourPayoutAddr == "" || theirPayoutAddr == "" {
		return errors.New("payout address missing")
	}

	ourPubKeys, err := parseKeys(ourKeys)
	if err != nil {
		return fmt.Errorf("error parsing their keys: %w", err)
	}

	theirPubKeys, err := parseKeys(theirKeys)
	if err != nil {
		return fmt.Errorf("error parsing our keys: %w", err)
	}

	err = matchKeys(ourChannels, ourPubKeys, theirPubKeys, chainParams)
	if err != nil {
		return err
	}

	// Let's prepare the PSBT.
	packet, err := psbt.NewFromUnsignedTx(wire.NewMsgTx(2))
	if err != nil {
		return fmt.Errorf("error creating PSBT from TX: %w", err)
	}

	// Let's now sum up the tally of how much of the rescued funds should
	// go to which party.
	var (
		ourSum    int64
		theirSum  int64
		estimator input.TxWeightEstimator
		signDescs = make(
			[]*input.SignDescriptor, 0, len(keys1.Channels),
		)
	)
	for idx, channel := range ourChannels {
		op, err := lnd.ParseOutpoint(channel.ChanPoint)
		if err != nil {
			return fmt.Errorf("error parsing channel out point: %w",
				err)
		}
		channel.txid = op.Hash.String()
		channel.vout = op.Index

		ourPart, theirPart, err := askAboutChannel(
			channel, idx+1, len(ourChannels), ourPayoutAddr,
			theirPayoutAddr,
		)
		if err != nil {
			return err
		}

		ourSum += ourPart
		theirSum += theirPart
		txIn := &wire.TxIn{
			PreviousOutPoint: *op,
		}
		pIn := psbt.PInput{
			WitnessScript: channel.witnessScript,
			WitnessUtxo: &wire.TxOut{
				PkScript: channel.pkScript,
				Value:    channel.Capacity,
			},
			// We'll be signing with our key, so we can just add the
			// other party's pubkey as additional info, so it's easy
			// for them to sign as well.
			Unknowns: []*psbt.Unknown{{
				Key:   PsbtKeyTypeOutputMissingSigPubkey,
				Value: channel.theirKey.SerializeCompressed(),
			}},
		}

		channelAddr, err := lnd.ParseAddress(
			channel.Address, chainParams,
		)
		if err != nil {
			return fmt.Errorf("error parsing channel address: %w",
				err)
		}

		prevOutFetcher := txscript.NewCannedPrevOutputFetcher(
			pIn.WitnessUtxo.PkScript, pIn.WitnessUtxo.Value,
		)
		signDesc := &input.SignDescriptor{
			KeyDesc: keychain.KeyDescriptor{
				PubKey: channel.ourKey,
				KeyLocator: keychain.KeyLocator{
					Family: keychain.KeyFamilyMultiSig,
					Index:  channel.ourKeyIndex,
				},
			},
			WitnessScript:     channel.witnessScript,
			Output:            pIn.WitnessUtxo,
			InputIndex:        idx,
			PrevOutputFetcher: prevOutFetcher,
		}

		switch a := channelAddr.(type) {
		case *btcutil.AddressWitnessScriptHash:
			estimator.AddWitnessInput(input.MultiSigWitnessSize)
			pIn.SighashType = txscript.SigHashAll
			signDesc.HashType = txscript.SigHashAll
			signDesc.SignMethod = input.WitnessV0SignMethod

		case *btcutil.AddressTaproot:
			estimator.AddTaprootKeySpendInput(
				txscript.SigHashDefault,
			)
			pIn.SighashType = txscript.SigHashDefault
			signDesc.HashType = txscript.SigHashDefault
			signDesc.SignMethod = input.TaprootKeySpendSignMethod

			err := addMuSig2Data(
				extendedKey, &pIn, channel, theirChannels[idx],
				op, a.WitnessProgram(),
			)
			if err != nil {
				return fmt.Errorf("error adding MuSig2 data: "+
					"%w", err)
			}

		default:
			return errors.New("unsupported address type for " +
				"channel address")
		}

		packet.UnsignedTx.TxIn = append(packet.UnsignedTx.TxIn, txIn)
		packet.Inputs = append(packet.Inputs, pIn)
		signDescs = append(signDescs, signDesc)
	}

	// Don't create dust.
	dustLimit := int64(lnwallet.DustLimitForSize(input.P2WSHSize))
	if ourSum < dustLimit {
		ourSum = 0
	}
	if theirSum < dustLimit {
		theirSum = 0
	}

	// Only add output for us if we should receive something.
	var ourOutput, theirOutput *wire.TxOut
	if ourSum > 0 {
		err = lnd.CheckAddress(
			ourPayoutAddr, chainParams, false, "our payout",
			lnd.AddrTypeP2WKH, lnd.AddrTypeP2TR,
		)
		if err != nil {
			return fmt.Errorf("error verifying our payout "+
				"address: %w", err)
		}

		pkScript, err := lnd.PrepareWalletAddress(
			ourPayoutAddr, chainParams, &estimator, nil,
			"our payout",
		)
		if err != nil {
			return fmt.Errorf("error preparing our payout "+
				"address: %w", err)
		}

		ourOutput = &wire.TxOut{
			PkScript: pkScript,
			Value:    ourSum,
		}
		packet.UnsignedTx.TxOut = append(
			packet.UnsignedTx.TxOut, ourOutput,
		)
		packet.Outputs = append(packet.Outputs, psbt.POutput{})
	}

	if theirSum > 0 {
		err = lnd.CheckAddress(
			theirPayoutAddr, chainParams, false, "their payout",
			lnd.AddrTypeP2WKH, lnd.AddrTypeP2TR,
		)
		if err != nil {
			return fmt.Errorf("error verifying their payout "+
				"address: %w", err)
		}

		pkScript, err := lnd.PrepareWalletAddress(
			theirPayoutAddr, chainParams, &estimator, nil,
			"their payout",
		)
		if err != nil {
			return fmt.Errorf("error preparing their payout "+
				"address: %w", err)
		}

		theirOutput = &wire.TxOut{
			PkScript: pkScript,
			Value:    theirSum,
		}
		packet.UnsignedTx.TxOut = append(
			packet.UnsignedTx.TxOut, theirOutput,
		)
		packet.Outputs = append(packet.Outputs, psbt.POutput{})
	}

	feeRateKWeight := chainfee.SatPerKVByte(
		1000 * c.FeeRate,
	).FeePerKWeight()
	totalFee := int64(feeRateKWeight.FeeForWeight(estimator.Weight()))

	fmt.Printf("Current tally (before fees):\n\t"+
		"To our address (%s): %d sats\n\t"+
		"To their address (%s): %d sats\n\t"+
		"Estimated fees (at rate %d sat/vByte): %d sats\n",
		ourPayoutAddr, ourSum, theirPayoutAddr, theirSum, c.FeeRate,
		totalFee)

	// Distribute the fees.
	halfFee := totalFee / 2
	switch {
	case ourSum-halfFee > 0 && theirSum-halfFee > 0:
		ourSum -= halfFee
		ourOutput.Value -= halfFee
		theirSum -= halfFee
		theirOutput.Value -= halfFee

	case ourSum-totalFee > 0:
		ourSum -= totalFee
		ourOutput.Value -= totalFee

	case theirSum-totalFee > 0:
		theirSum -= totalFee
		theirOutput.Value -= totalFee

	default:
		return errors.New("error distributing fees, unhandled case")
	}

	fmt.Printf("Current tally (after fees):\n\t"+
		"To our address (%s): %d sats\n\t"+
		"To their address (%s): %d sats\n",
		ourPayoutAddr, ourSum, theirPayoutAddr, theirSum)

	// Loop a second time through the inputs and sign each input. We now
	// have all the witness/non-witness data filled in the psbt package.
	signer := &lnd.Signer{
		ExtendedKey: extendedKey,
		ChainParams: chainParams,
	}
	for idx := range packet.UnsignedTx.TxIn {
		signDesc := signDescs[idx]

		// If we're dealing with a taproot channel, we'll need to
		// create a MuSig2 partial signature.
		if signDesc.SignMethod == input.TaprootKeySpendSignMethod {
			err := muSig2PartialSign(
				signer, &signDesc.KeyDesc, packet, idx,
			)
			if err != nil {
				return fmt.Errorf("error creating MuSig2 "+
					"partial signature: %w", err)
			}

			continue
		}

		ourSigRaw, err := signer.SignOutputRaw(
			packet.UnsignedTx, signDesc,
		)
		if err != nil {
			return fmt.Errorf("error signing with our key: %w", err)
		}
		ourSig := append(ourSigRaw.Serialize(), byte(signDesc.HashType))

		// Great, we were able to create our sig, let's add it to the
		// PSBT.
		updater, err := psbt.NewUpdater(packet)
		if err != nil {
			return fmt.Errorf("error creating PSBT updater: %w",
				err)
		}
		status, err := updater.Sign(
			idx, ourSig,
			signDesc.KeyDesc.PubKey.SerializeCompressed(), nil,
			signDesc.WitnessScript,
		)
		if err != nil {
			return fmt.Errorf("error adding signature to PSBT: %w",
				err)
		}
		if status != 0 {
			return fmt.Errorf("unexpected status for signature "+
				"update, got %d wanted 0", status)
		}
	}

	// Looks like we're done!
	base64, err := packet.B64Encode()
	if err != nil {
		return fmt.Errorf("error encoding PSBT: %w", err)
	}

	fmt.Printf("Done creating offer, please send this PSBT string to \n"+
		"the other party to review and sign (if they accept): \n%s\n",
		base64)

	return nil
}

// parseKeys parses a list of string keys into public keys.
func parseKeys(keys []string) ([]*btcec.PublicKey, error) {
	pubKeys := make([]*btcec.PublicKey, 0, len(keys))
	for _, key := range keys {
		pubKey, err := pubKeyFromHex(key)
		if err != nil {
			return nil, err
		}
		pubKeys = append(pubKeys, pubKey)
	}

	return pubKeys, nil
}

// matchKeys tries to match the keys from the two nodes. It updates the channels
// with the correct keys and witness scripts.
func matchKeys(channels []*channel, ourPubKeys, theirPubKeys []*btcec.PublicKey,
	chainParams *chaincfg.Params) error {

	// Loop through all channels and all keys now, this will definitely take
	// a while.
channelLoop:
	for _, channel := range channels {
		for ourKeyIndex, ourKey := range ourPubKeys {
			for _, theirKey := range theirPubKeys {
				match, witScript, pkScript, err := matchScript(
					channel.Address, ourKey, theirKey,
					chainParams,
				)
				if err != nil {
					return fmt.Errorf("error matching "+
						"keys to script: %w", err)
				}

				if match {
					channel.ourKeyIndex = uint32(ourKeyIndex)
					channel.ourKey = ourKey
					channel.theirKey = theirKey
					channel.witnessScript = witScript
					channel.pkScript = pkScript

					log.Infof("Found keys for channel %s: "+
						"our key %x, their key %x",
						channel.ChanPoint,
						ourKey.SerializeCompressed(),
						theirKey.SerializeCompressed())

					continue channelLoop
				}
			}
		}

		return fmt.Errorf("didn't find matching multisig keys for "+
			"channel %s", channel.ChanPoint)
	}

	return nil
}

func matchScript(address string, key1, key2 *btcec.PublicKey,
	params *chaincfg.Params) (bool, []byte, []byte, error) {

	addr, err := lnd.ParseAddress(address, params)
	if err != nil {
		return false, nil, nil, fmt.Errorf("error parsing channel "+
			"funding address '%s': %w", address, err)
	}

	channelScript, err := txscript.PayToAddrScript(addr)
	if err != nil {
		return false, nil, nil, err
	}

	switch addr.(type) {
	case *btcutil.AddressWitnessScriptHash:
		witnessScript, err := input.GenMultiSigScript(
			key1.SerializeCompressed(), key2.SerializeCompressed(),
		)
		if err != nil {
			return false, nil, nil, err
		}
		pkScript, err := input.WitnessScriptHash(witnessScript)
		if err != nil {
			return false, nil, nil, err
		}

		return bytes.Equal(channelScript, pkScript), witnessScript,
			pkScript, nil

	case *btcutil.AddressTaproot:
		// FIXME: fill tapscriptRoot.
		var tapscriptRoot fn.Option[chainhash.Hash]

		pkScript, _, err := input.GenTaprootFundingScript(
			key1, key2, 0, tapscriptRoot,
		)
		if err != nil {
			return false, nil, nil, err
		}

		return bytes.Equal(channelScript, pkScript), nil, pkScript, nil

	default:
		return false, nil, nil, fmt.Errorf("unsupported address type "+
			"for channel funding address: %T", addr)
	}
}

func askAboutChannel(channel *channel, current, total int, ourAddr,
	theirAddr string) (int64, int64, error) {

	fundingTxid := strings.Split(channel.ChanPoint, ":")[0]

	fmt.Printf("Channel %s (%d of %d): \n\tCapacity: %d sat\n\t"+
		"Funding TXID: https://blockstream.info/tx/%v\n\t"+
		"Channel info: https://1ml.com/channel/%s\n\t"+
		"Channel funding address: %s\n\n"+
		"How many sats should go to you (%s) before fees?: ",
		channel.ChanPoint, current, total, channel.Capacity,
		fundingTxid, channel.ChannelID, channel.Address, ourAddr)
	reader := bufio.NewReader(os.Stdin)
	ourPartStr, err := reader.ReadString('\n')
	if err != nil {
		return 0, 0, err
	}

	ourPart, err := strconv.ParseUint(strings.TrimSpace(ourPartStr), 10, 64)
	if err != nil {
		return 0, 0, err
	}

	// Let the user try again if they entered something incorrect.
	if int64(ourPart) > channel.Capacity {
		fmt.Printf("Cannot send more than %d sats to ourself!\n",
			channel.Capacity)
		return askAboutChannel(
			channel, current, total, ourAddr, theirAddr,
		)
	}

	theirPart := channel.Capacity - int64(ourPart)
	fmt.Printf("\nWill send: \n\t%d sats to our address (%s) and \n\t"+
		"%d sats to the other peer's address (%s).\n\n", ourPart,
		ourAddr, theirPart, theirAddr)

	return int64(ourPart), theirPart, nil
}

func addMuSig2Data(extendedKey *hdkeychain.ExtendedKey, pIn *psbt.PInput,
	ourChannel, theirChannel *channel, channelPoint *wire.OutPoint,
	xOnlyPubKey []byte) error {

	aggKey, err := schnorr.ParsePubKey(xOnlyPubKey)
	if err != nil {
		return fmt.Errorf("error parsing x-only pubkey: %w", err)
	}

	ourRandomnessBytes, err := hex.DecodeString(
		ourChannel.MuSig2NonceRandomness,
	)
	if err != nil {
		return fmt.Errorf("error decoding nonce randomness: %w", err)
	}

	theirRandomnessBytes, err := hex.DecodeString(
		theirChannel.MuSig2NonceRandomness,
	)
	if err != nil {
		return fmt.Errorf("error decoding nonce randomness: %w", err)
	}

	ourNonceBytes, err := hex.DecodeString(ourChannel.MuSig2Nonces)
	if err != nil {
		return fmt.Errorf("error decoding nonce: %w", err)
	}

	theirNonceBytes, err := hex.DecodeString(theirChannel.MuSig2Nonces)
	if err != nil {
		return fmt.Errorf("error decoding nonce: %w", err)
	}

	// We first make sure that the nonces we got are correct, and we created
	// them initially, before we create new ones (to avoid security issues
	// when signing multiple offers).
	var ourRandomness [32]byte
	copy(ourRandomness[:], ourRandomnessBytes)
	ourNonces, err := lnd.GenerateMuSig2Nonces(
		extendedKey, ourRandomness, channelPoint, chainParams, nil,
	)
	if err != nil {
		return fmt.Errorf("error generating MuSig2 nonces: %w", err)
	}

	if !bytes.Equal(ourNonces.PubNonce[:], ourNonceBytes) {
		return errors.New("MuSig2 nonces don't match")
	}

	// Because at this point we're going to create a partial signature, we
	// create a new nonce pair for the session. This is to make sure that
	// the nonce is unique for each session, in case we're signing multiple
	// offers.
	if _, err := rand.Read(ourRandomness[:]); err != nil {
		return fmt.Errorf("error generating randomness: %w", err)
	}

	ourNonces, err = lnd.GenerateMuSig2Nonces(
		extendedKey, ourRandomness, channelPoint, chainParams, nil,
	)
	if err != nil {
		return fmt.Errorf("error generating MuSig2 nonces: %w", err)
	}

	var theirNonces [musig2.PubNonceSize]byte
	copy(theirNonces[:], theirNonceBytes)

	pIn.MuSig2PubNonces = append(pIn.MuSig2PubNonces, &psbt.MuSig2PubNonce{
		PubKey:       ourChannel.ourKey,
		AggregateKey: aggKey,
		TapLeafHash:  ourRandomness[:],
		PubNonce:     ourNonces.PubNonce,
	}, &psbt.MuSig2PubNonce{
		PubKey:       ourChannel.theirKey,
		AggregateKey: aggKey,
		TapLeafHash:  theirRandomnessBytes,
		PubNonce:     theirNonces,
	})

	return nil
}

func muSig2PartialSign(signer *lnd.Signer, keyDesc *keychain.KeyDescriptor,
	packet *psbt.Packet, idx int) error {

	signingKey, err := signer.FetchPrivateKey(keyDesc)
	if err != nil {
		return fmt.Errorf("error fetching private key: %w", err)
	}

	pIn := packet.Inputs[idx]
	if len(pIn.MuSig2PubNonces) != 2 {
		return fmt.Errorf("expected 2 MuSig2 nonces in packet input, "+
			"got %d", len(pIn.MuSig2PubNonces))
	}
	channelPoint := &packet.UnsignedTx.TxIn[idx].PreviousOutPoint

	var ourNonces, theirNonces *psbt.MuSig2PubNonce
	for idx := range pIn.MuSig2PubNonces {
		nonce := pIn.MuSig2PubNonces[idx]
		if nonce.PubKey.IsEqual(keyDesc.PubKey) {
			ourNonces = nonce
		} else {
			theirNonces = nonce
		}
	}
	if ourNonces == nil || theirNonces == nil {
		return errors.New("couldn't find our or their nonce")
	}

	keys := []*btcec.PublicKey{ourNonces.PubKey, theirNonces.PubKey}
	aggKey, _, _, err := musig2.AggregateKeys(
		keys, true, musig2.WithBIP86KeyTweak(),
	)
	if err != nil {
		return fmt.Errorf("error aggregating keys: %w", err)
	}

	ctx, err := musig2.NewContext(
		signingKey, true, musig2.WithBip86TweakCtx(),
		musig2.WithKnownSigners(keys),
	)
	if err != nil {
		return fmt.Errorf("error creating MuSig2 context: %w", err)
	}

	// Check that the randomness in the tap leaf hash is correct. We'll then
	// later check that it also corresponds to the public nonces.
	var emptyHash [32]byte
	if len(ourNonces.TapLeafHash) != sha256.Size ||
		bytes.Equal(ourNonces.TapLeafHash, emptyHash[:]) {

		return errors.New("invalid nonce randomness in tap leaf hash")
	}

	// Generate the secure nonces from the information we got. We use the
	// tap leaf hash to transport our randomness.
	var ourRandomness [32]byte
	copy(ourRandomness[:], ourNonces.TapLeafHash)
	ourSecNonces, err := lnd.GenerateMuSig2Nonces(
		signer.ExtendedKey, ourRandomness, channelPoint, chainParams,
		signingKey,
	)
	if err != nil {
		return fmt.Errorf("error generating MuSig2 nonces: %w", err)
	}

	// Make sure the re-derived nonces match the public nonces in the PSBT.
	if !bytes.Equal(ourSecNonces.PubNonce[:], ourNonces.PubNonce[:]) {
		return errors.New("re-derived public nonce doesn't match")
	}

	sess, err := ctx.NewSession(musig2.WithPreGeneratedNonce(ourSecNonces))
	if err != nil {
		return fmt.Errorf("error creating MuSig2 session: %w", err)
	}

	haveAll, err := sess.RegisterPubNonce(theirNonces.PubNonce)
	if err != nil {
		return fmt.Errorf("error registering remote nonce: %w", err)
	}

	if !haveAll {
		return errors.New("didn't receive all nonces")
	}

	prevOutFetcher := wallet.PsbtPrevOutputFetcher(packet)
	sigHashes := txscript.NewTxSigHashes(packet.UnsignedTx, prevOutFetcher)
	sigHash, err := txscript.CalcTaprootSignatureHash(
		sigHashes, packet.Inputs[idx].SighashType, packet.UnsignedTx,
		idx, prevOutFetcher,
	)
	if err != nil {
		return fmt.Errorf("error calculating signature hash: %w", err)
	}

	var sigHashMsg [32]byte
	copy(sigHashMsg[:], sigHash)
	partialSig, err := sess.Sign(sigHashMsg, musig2.WithSortedKeys())
	if err != nil {
		return fmt.Errorf("error signing with MuSig2: %w", err)
	}

	psbtPartialSig := &psbt.MuSig2PartialSig{
		PubKey:       ourNonces.PubKey,
		AggregateKey: aggKey.PreTweakedKey,
		PartialSig:   *partialSig,
	}
	packet.Inputs[idx].MuSig2PartialSigs = append(
		packet.Inputs[idx].MuSig2PartialSigs, psbtPartialSig,
	)

	return nil
}
