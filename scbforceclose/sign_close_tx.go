package scbforceclose

import (
	"errors"
	"fmt"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/lightningnetwork/lnd/chanbackup"
	"github.com/lightningnetwork/lnd/channeldb"
	"github.com/lightningnetwork/lnd/fn"
	"github.com/lightningnetwork/lnd/input"
	"github.com/lightningnetwork/lnd/keychain"
	"github.com/lightningnetwork/lnd/lnwallet"
	"github.com/lightningnetwork/lnd/shachain"
)

// SignCloseTx produces a signed commit tx from a channel backup.
func SignCloseTx(s chanbackup.Single, keyRing keychain.KeyRing,
	ecdher keychain.ECDHRing, signer input.Signer) (*wire.MsgTx, error) {

	var errNoInputs = errors.New("channel backup does not have data " +
		"needed to sign force close tx")

	closeTxInputs, err := s.CloseTxInputs.UnwrapOrErr(errNoInputs)
	if err != nil {
		return nil, err
	}

	// Each of the keys in our local channel config only have their
	// locators populated, so we'll re-derive the raw key now.
	localMultiSigKey, err := keyRing.DeriveKey(
		s.LocalChanCfg.MultiSigKey.KeyLocator,
	)
	if err != nil {
		return nil, fmt.Errorf("unable to derive multisig key: %w", err)
	}

	// Determine the value of tapscriptRoot option.
	tapscriptRootOpt := fn.None[chainhash.Hash]()
	if s.Version.HasTapscriptRoot() {
		tapscriptRootOpt = closeTxInputs.TapscriptRoot
	}

	// Create signature descriptor.
	signDesc, err := createSignDesc(
		localMultiSigKey, s.RemoteChanCfg.MultiSigKey.PubKey,
		s.Version, s.Capacity, tapscriptRootOpt,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create signDesc: %w", err)
	}

	// Build inputs for GetSignedCommitTx.
	inputs := lnwallet.SignedCommitTxInputs{
		CommitTx:  closeTxInputs.CommitTx,
		CommitSig: closeTxInputs.CommitSig,
		OurKey:    localMultiSigKey,
		TheirKey:  s.RemoteChanCfg.MultiSigKey,
		SignDesc:  signDesc,
	}

	// Add special fields in case of a taproot channel.
	if s.Version.IsTaproot() {
		producer, err := createTaprootNonceProducer(
			s.ShaChainRootDesc, localMultiSigKey.PubKey, ecdher,
		)
		if err != nil {
			return nil, err
		}
		inputs.Taproot = fn.Some(lnwallet.TaprootSignedCommitTxInputs{
			CommitHeight:         closeTxInputs.CommitHeight,
			TaprootNonceProducer: producer,
			TapscriptRoot:        tapscriptRootOpt,
		})
	}

	return lnwallet.GetSignedCommitTx(inputs, signer)
}

// createSignDesc creates SignDescriptor from local and remote keys,
// backup version and capacity.
// See LightningChannel.createSignDesc on how signDesc is produced.
func createSignDesc(localMultiSigKey keychain.KeyDescriptor,
	remoteKey *btcec.PublicKey, version chanbackup.SingleBackupVersion,
	capacity btcutil.Amount, tapscriptRoot fn.Option[chainhash.Hash]) (
	*input.SignDescriptor, error) {

	var fundingPkScript, multiSigScript []byte

	localKey := localMultiSigKey.PubKey

	var err error
	if version.IsTaproot() {
		fundingPkScript, _, err = input.GenTaprootFundingScript(
			localKey, remoteKey, int64(capacity), tapscriptRoot,
		)
		if err != nil {
			return nil, err
		}
	} else {
		multiSigScript, err = input.GenMultiSigScript(
			localKey.SerializeCompressed(),
			remoteKey.SerializeCompressed(),
		)
		if err != nil {
			return nil, err
		}

		fundingPkScript, err = input.WitnessScriptHash(multiSigScript)
		if err != nil {
			return nil, err
		}
	}

	return &input.SignDescriptor{
		KeyDesc:       localMultiSigKey,
		WitnessScript: multiSigScript,
		Output: &wire.TxOut{
			PkScript: fundingPkScript,
			Value:    int64(capacity),
		},
		HashType: txscript.SigHashAll,
		PrevOutputFetcher: txscript.NewCannedPrevOutputFetcher(
			fundingPkScript, int64(capacity),
		),
		InputIndex: 0,
	}, nil
}

// createTaprootNonceProducer makes taproot nonce producer from a
// ShaChainRootDesc and our public multisig key.
func createTaprootNonceProducer(shaChainRootDesc keychain.KeyDescriptor,
	localKey *btcec.PublicKey, ecdher keychain.ECDHRing) (shachain.Producer,
	error) {

	if shaChainRootDesc.PubKey != nil {
		return nil, errors.New("taproot channels always use ECDH, " +
			"but legacy ShaChainRootDesc with pubkey found")
	}

	// This is the scheme in which the shachain root is derived via an ECDH
	// operation on the private key of ShaChainRootDesc and our public
	// multisig key.
	ecdh, err := ecdher.ECDH(shaChainRootDesc, localKey)
	if err != nil {
		return nil, fmt.Errorf("ecdh failed: %w", err)
	}

	// The shachain root that seeds RevocationProducer for this channel.
	revRoot := chainhash.Hash(ecdh)

	revocationProducer := shachain.NewRevocationProducer(revRoot)

	return channeldb.DeriveMusig2Shachain(revocationProducer)
}
