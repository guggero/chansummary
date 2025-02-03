package main

import (
	"bytes"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/btcutil/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/lightninglabs/chantools/btc"
	"github.com/lightninglabs/chantools/lnd"
	"github.com/lightningnetwork/lnd/input"
	"github.com/lightningnetwork/lnd/keychain"
	"github.com/lightningnetwork/lnd/lnwallet/chainfee"
	"github.com/spf13/cobra"
)

//go:embed sweepremoteclosed_ancient.json
var ancientChannelPoints []byte

const (
	sweepRemoteClosedDefaultRecoveryWindow = 200
	sweepDustLimit                         = 600
)

type sweepRemoteClosedCommand struct {
	RecoveryWindow uint32
	APIURL         string
	Publish        bool
	SweepAddr      string
	FeeRate        uint32

	rootKey *rootKey
	cmd     *cobra.Command
}

func newSweepRemoteClosedCommand() *cobra.Command {
	cc := &sweepRemoteClosedCommand{}
	cc.cmd = &cobra.Command{
		Use: "sweepremoteclosed",
		Short: "Go through all the addresses that could have funds of " +
			"channels that were force-closed by the remote party. " +
			"A public block explorer is queried for each address " +
			"and if any balance is found, all funds are swept to " +
			"a given address",
		Long: `This command helps users sweep funds that are in 
outputs of channels that were force-closed by the remote party. This command
only needs to be used if no channel.backup file is available. By manually
contacting the remote peers and asking them to force-close the channels, the
funds can be swept after the force-close transaction was confirmed.

Supported remote force-closed channel types are:
 - STATIC_REMOTE_KEY (a.k.a. tweakless channels)
 - ANCHOR (a.k.a. anchor output channels)
 - SIMPLE_TAPROOT (a.k.a. simple taproot channels)
`,
		Example: `chantools sweepremoteclosed \
	--recoverywindow 300 \
	--feerate 20 \
	--sweepaddr bc1q..... \
  	--publish`,
		RunE: cc.Execute,
	}
	cc.cmd.Flags().Uint32Var(
		&cc.RecoveryWindow, "recoverywindow",
		sweepRemoteClosedDefaultRecoveryWindow, "number of keys to "+
			"scan per derivation path",
	)
	cc.cmd.Flags().StringVar(
		&cc.APIURL, "apiurl", defaultAPIURL, "API URL to use (must "+
			"be esplora compatible)",
	)
	cc.cmd.Flags().BoolVar(
		&cc.Publish, "publish", false, "publish sweep TX to the chain "+
			"API instead of just printing the TX",
	)
	cc.cmd.Flags().StringVar(
		&cc.SweepAddr, "sweepaddr", "", "address to recover the funds "+
			"to; specify '"+lnd.AddressDeriveFromWallet+"' to "+
			"derive a new address from the seed automatically",
	)
	cc.cmd.Flags().Uint32Var(
		&cc.FeeRate, "feerate", defaultFeeSatPerVByte, "fee rate to "+
			"use for the sweep transaction in sat/vByte",
	)

	cc.rootKey = newRootKey(cc.cmd, "sweeping the wallet")

	return cc.cmd
}

func (c *sweepRemoteClosedCommand) Execute(_ *cobra.Command, _ []string) error {
	extendedKey, err := c.rootKey.read()
	if err != nil {
		return fmt.Errorf("error reading root key: %w", err)
	}

	// Make sure sweep addr is set.
	err = lnd.CheckAddress(
		c.SweepAddr, chainParams, true, "sweep", lnd.AddrTypeP2WKH,
		lnd.AddrTypeP2TR,
	)
	if err != nil {
		return err
	}

	// Set default values.
	if c.RecoveryWindow == 0 {
		c.RecoveryWindow = sweepRemoteClosedDefaultRecoveryWindow
	}
	if c.FeeRate == 0 {
		c.FeeRate = defaultFeeSatPerVByte
	}

	return sweepRemoteClosed(
		extendedKey, c.APIURL, c.SweepAddr, c.RecoveryWindow, c.FeeRate,
		c.Publish,
	)
}

type utxo struct {
	wire.TxOut
	wire.OutPoint
}

type targetAddr struct {
	addr       btcutil.Address
	keyDesc    *keychain.KeyDescriptor
	tweak      []byte
	utxos      []*utxo
	script     []byte
	scriptTree *input.CommitScriptTree
}

func sweepRemoteClosed(extendedKey *hdkeychain.ExtendedKey, apiURL,
	sweepAddr string, recoveryWindow uint32, feeRate uint32,
	publish bool) error {

	var estimator input.TxWeightEstimator
	sweepScript, err := lnd.PrepareWalletAddress(
		sweepAddr, chainParams, &estimator, extendedKey, "sweep",
	)
	if err != nil {
		return err
	}

	var (
		targets []*targetAddr
		api     = newExplorerAPI(apiURL)
	)
	for index := range recoveryWindow {
		path := fmt.Sprintf("m/1017'/%d'/%d'/0/%d",
			chainParams.HDCoinType, keychain.KeyFamilyPaymentBase,
			index)
		parsedPath, err := lnd.ParsePath(path)
		if err != nil {
			return fmt.Errorf("error parsing path: %w", err)
		}

		hdKey, err := lnd.DeriveChildren(
			extendedKey, parsedPath,
		)
		if err != nil {
			return fmt.Errorf("eror deriving children: %w", err)
		}

		privKey, err := hdKey.ECPrivKey()
		if err != nil {
			return fmt.Errorf("could not derive private "+
				"key: %w", err)
		}

		foundTargets, err := queryAddressBalances(
			privKey.PubKey(), path, &keychain.KeyDescriptor{
				PubKey: privKey.PubKey(),
				KeyLocator: keychain.KeyLocator{
					Family: keychain.KeyFamilyPaymentBase,
					Index:  index,
				},
			}, api,
		)
		if err != nil {
			return fmt.Errorf("could not query API for "+
				"addresses with funds: %w", err)
		}
		targets = append(targets, foundTargets...)
	}

	// Also check if there are any funds in channels with the initial,
	// tweaked channel type that requires a channel point.
	ancientChannelTargets, err := checkAncientChannelPoints(
		api, recoveryWindow, extendedKey,
	)
	if err != nil && !errors.Is(err, errAddrNotFound) {
		return fmt.Errorf("could not check ancient channel points: %w",
			err)
	}

	if len(ancientChannelTargets) > 0 {
		targets = append(targets, ancientChannelTargets...)
	}

	// Create estimator and transaction template.
	var (
		signDescs        []*input.SignDescriptor
		sweepTx          = wire.NewMsgTx(2)
		totalOutputValue = uint64(0)
		prevOutFetcher   = txscript.NewMultiPrevOutFetcher(nil)
	)

	// Add all found target outputs.
	for _, target := range targets {
		for _, utxo := range target.utxos {
			totalOutputValue += uint64(utxo.Value)

			prevOutFetcher.AddPrevOut(utxo.OutPoint, &utxo.TxOut)
			txIn := &wire.TxIn{
				PreviousOutPoint: utxo.OutPoint,
				Sequence:         wire.MaxTxInSequenceNum,
			}
			sweepTx.TxIn = append(sweepTx.TxIn, txIn)
			inputIndex := len(sweepTx.TxIn) - 1

			var signDesc *input.SignDescriptor
			switch target.addr.(type) {
			case *btcutil.AddressWitnessPubKeyHash:
				estimator.AddP2WKHInput()

				signDesc = &input.SignDescriptor{
					KeyDesc:           *target.keyDesc,
					WitnessScript:     target.script,
					SingleTweak:       target.tweak,
					Output:            &utxo.TxOut,
					HashType:          txscript.SigHashAll,
					PrevOutputFetcher: prevOutFetcher,
					InputIndex:        inputIndex,
				}

			case *btcutil.AddressWitnessScriptHash:
				estimator.AddWitnessInput(
					input.ToRemoteConfirmedWitnessSize,
				)
				txIn.Sequence = 1

				signDesc = &input.SignDescriptor{
					KeyDesc:           *target.keyDesc,
					WitnessScript:     target.script,
					Output:            &utxo.TxOut,
					HashType:          txscript.SigHashAll,
					PrevOutputFetcher: prevOutFetcher,
					InputIndex:        inputIndex,
				}

			case *btcutil.AddressTaproot:
				estimator.AddWitnessInput(
					input.TaprootToRemoteWitnessSize,
				)
				txIn.Sequence = 1

				tree := target.scriptTree
				controlBlock, err := tree.CtrlBlockForPath(
					input.ScriptPathSuccess,
				)
				if err != nil {
					return err
				}
				controlBlockBytes, err := controlBlock.ToBytes()
				if err != nil {
					return err
				}

				script := tree.SettleLeaf.Script
				signMethod := input.TaprootScriptSpendSignMethod
				signDesc = &input.SignDescriptor{
					KeyDesc:           *target.keyDesc,
					WitnessScript:     script,
					Output:            &utxo.TxOut,
					HashType:          txscript.SigHashDefault,
					PrevOutputFetcher: prevOutFetcher,
					ControlBlock:      controlBlockBytes,
					InputIndex:        inputIndex,
					SignMethod:        signMethod,
					TapTweak:          tree.TapscriptRoot,
				}
			}

			signDescs = append(signDescs, signDesc)
		}
	}

	if len(targets) == 0 || totalOutputValue < sweepDustLimit {
		return fmt.Errorf("found %d sweep targets with total value "+
			"of %d satoshis which is below the dust limit of %d",
			len(targets), totalOutputValue, sweepDustLimit)
	}

	// Calculate the fee based on the given fee rate and our weight
	// estimation.
	feeRateKWeight := chainfee.SatPerKVByte(1000 * feeRate).FeePerKWeight()
	totalFee := feeRateKWeight.FeeForWeight(estimator.Weight())

	log.Infof("Fee %d sats of %d total amount (estimated weight %d)",
		totalFee, totalOutputValue, estimator.Weight())

	sweepTx.TxOut = []*wire.TxOut{{
		Value:    int64(totalOutputValue) - int64(totalFee),
		PkScript: sweepScript,
	}}

	// Sign the transaction now.
	var (
		signer = &lnd.Signer{
			ExtendedKey: extendedKey,
			ChainParams: chainParams,
		}
		sigHashes = txscript.NewTxSigHashes(sweepTx, prevOutFetcher)
	)
	for idx, desc := range signDescs {
		desc.SigHashes = sigHashes
		desc.InputIndex = idx

		switch {
		// Simple Taproot Channels.
		case desc.SignMethod == input.TaprootScriptSpendSignMethod:
			witness, err := input.TaprootCommitSpendSuccess(
				signer, desc, sweepTx, nil,
			)
			if err != nil {
				return err
			}
			sweepTx.TxIn[idx].Witness = witness

		// Anchor Channels.
		case len(desc.WitnessScript) > 0:
			witness, err := input.CommitSpendToRemoteConfirmed(
				signer, desc, sweepTx,
			)
			if err != nil {
				return err
			}
			sweepTx.TxIn[idx].Witness = witness

		// Static Remote Key Channels.
		default:
			// The txscript library expects the witness script of a
			// P2WKH descriptor to be set to the pkScript of the
			// output...
			desc.WitnessScript = desc.Output.PkScript
			witness, err := input.CommitSpendNoDelay(
				signer, desc, sweepTx, true,
			)
			if err != nil {
				return err
			}
			sweepTx.TxIn[idx].Witness = witness
		}
	}

	var buf bytes.Buffer
	err = sweepTx.Serialize(&buf)
	if err != nil {
		return err
	}

	// Publish TX.
	if publish {
		response, err := api.PublishTx(
			hex.EncodeToString(buf.Bytes()),
		)
		if err != nil {
			return err
		}
		log.Infof("Published TX %s, response: %s",
			sweepTx.TxHash().String(), response)
	}

	log.Infof("Transaction: %x", buf.Bytes())
	return nil
}

func queryAddressBalances(pubKey *btcec.PublicKey, path string,
	keyDesc *keychain.KeyDescriptor, api *btc.ExplorerAPI) ([]*targetAddr,
	error) {

	var targets []*targetAddr
	queryAddr := func(address btcutil.Address, script []byte,
		scriptTree *input.CommitScriptTree) error {

		unspent, err := api.Unspent(address.EncodeAddress())
		if err != nil {
			return fmt.Errorf("could not query unspent: %w", err)
		}

		if len(unspent) > 0 {
			log.Infof("Found %d unspent outputs for address %v",
				len(unspent), address.EncodeAddress())

			utxos, err := parseUtxos(unspent)
			if err != nil {
				return err
			}

			targets = append(targets, &targetAddr{
				addr:       address,
				keyDesc:    keyDesc,
				utxos:      utxos,
				script:     script,
				scriptTree: scriptTree,
			})
		}

		return nil
	}

	p2wkh, err := lnd.P2WKHAddr(pubKey, chainParams)
	if err != nil {
		return nil, err
	}
	if err := queryAddr(p2wkh, nil, nil); err != nil {
		return nil, err
	}

	p2anchor, script, err := lnd.P2AnchorStaticRemote(pubKey, chainParams)
	if err != nil {
		return nil, err
	}
	if err := queryAddr(p2anchor, script, nil); err != nil {
		return nil, err
	}

	p2tr, scriptTree, err := lnd.P2TaprootStaticRemote(pubKey, chainParams)
	if err != nil {
		return nil, err
	}
	if err := queryAddr(p2tr, nil, scriptTree); err != nil {
		return nil, err
	}

	return targets, nil
}

func parseUtxos(vouts []*btc.Vout) ([]*utxo, error) {
	utxos := make([]*utxo, len(vouts))
	for idx, vout := range vouts {
		txHash, err := chainhash.NewHashFromStr(vout.Outspend.Txid)
		if err != nil {
			return nil, fmt.Errorf("error parsing tx hash: %w", err)
		}

		pkScript, err := hex.DecodeString(vout.ScriptPubkey)
		if err != nil {
			return nil, fmt.Errorf("error decoding script pubkey: "+
				"%w", err)
		}

		utxos[idx] = &utxo{
			TxOut: wire.TxOut{
				PkScript: pkScript,
				Value:    int64(vout.Value),
			},
			OutPoint: wire.OutPoint{
				Hash:  *txHash,
				Index: uint32(vout.Outspend.Vin),
			},
		}

	}

	return utxos, nil
}

type ancientChannel struct {
	OP   string `json:"close_outpoint"`
	Addr string `json:"close_addr"`
	CP   string `json:"commit_point"`
}

func findAncientChannels(channels []ancientChannel, numKeys uint32,
	key *hdkeychain.ExtendedKey) ([]ancientChannel, error) {

	if err := fillCache(numKeys, key); err != nil {
		return nil, err
	}

	var foundChannels []ancientChannel
	for _, channel := range channels {
		// Decode the commit point.
		commitPointBytes, err := hex.DecodeString(channel.CP)
		if err != nil {
			return nil, fmt.Errorf("unable to decode commit "+
				"point: %w", err)
		}
		commitPoint, err := btcec.ParsePubKey(commitPointBytes)
		if err != nil {
			return nil, fmt.Errorf("unable to parse commit "+
				"point: %w", err)
		}

		// Create the address for the commit key.
		addr, err := lnd.ParseAddress(channel.Addr, chainParams)
		if err != nil {
			return nil, err
		}

		_, _, err = keyInCache(numKeys, addr.String(), commitPoint)
		switch {
		case err == nil:
			foundChannels = append(foundChannels, channel)

		case errors.Is(err, errAddrNotFound):
			// Try next address.

		default:
			return nil, err
		}
	}

	return foundChannels, nil
}

func checkAncientChannelPoints(api *btc.ExplorerAPI, numKeys uint32,
	key *hdkeychain.ExtendedKey) ([]*targetAddr, error) {

	var channels []ancientChannel
	err := json.Unmarshal(ancientChannelPoints, &channels)
	if err != nil {
		return nil, err
	}

	ancientChannels, err := findAncientChannels(channels, numKeys, key)
	if err != nil {
		return nil, err
	}

	var targets []*targetAddr
	for _, ancientChannel := range ancientChannels {
		op, err := lnd.ParseOutpoint(ancientChannel.OP)
		if err != nil {
			return nil, fmt.Errorf("unable to parse outpoint: %w",
				err)
		}

		// Decode the commit point.
		commitPointBytes, err := hex.DecodeString(ancientChannel.CP)
		if err != nil {
			return nil, fmt.Errorf("unable to decode commit "+
				"point: %w", err)
		}
		commitPoint, err := btcec.ParsePubKey(commitPointBytes)
		if err != nil {
			return nil, fmt.Errorf("unable to parse commit point: "+
				"%w", err)
		}

		// Create the address for the commit key.
		addr, err := lnd.ParseAddress(ancientChannel.Addr, chainParams)
		if err != nil {
			return nil, err
		}

		log.Infof("Found private key for address %v in list of "+
			"ancient channels!", addr)

		tx, err := api.Transaction(op.Hash.String())
		if err != nil {
			return nil, fmt.Errorf("could not query transaction: "+
				"%w", err)
		}

		pkScript, err := hex.DecodeString(
			tx.Vout[op.Index].ScriptPubkey,
		)
		if err != nil {
			return nil, fmt.Errorf("could not decode script "+
				"pubkey: %w", err)
		}

		txOut := wire.TxOut{
			Value:    int64(tx.Vout[op.Index].Value),
			PkScript: pkScript,
		}

		keyDesc, tweak, err := keyInCache(
			numKeys, addr.String(), commitPoint,
		)
		if err != nil {
			return nil, err
		}

		targets = append(targets, &targetAddr{
			addr:    addr,
			keyDesc: keyDesc,
			tweak:   tweak,
			utxos: []*utxo{{
				OutPoint: *op,
				TxOut:    txOut,
			}},
		})
	}

	return targets, nil
}
