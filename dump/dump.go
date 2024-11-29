package dump

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"net"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/lightningnetwork/lnd/chanbackup"
	"github.com/lightningnetwork/lnd/channeldb"
	"github.com/lightningnetwork/lnd/input"
	"github.com/lightningnetwork/lnd/keychain"
	"github.com/lightningnetwork/lnd/lntypes"
	"github.com/lightningnetwork/lnd/lnwallet"
	"github.com/lightningnetwork/lnd/lnwire"
)

const (
	lndInternalDerivationPath = "m/1017'/%d'/%d'/0/%d"
)

// BackupMulti is the information we want to dump from a lnd channel backup
// multi file. See `chanbackup.Multi` for information about the fields.
type BackupMulti struct {
	Version       chanbackup.MultiBackupVersion
	StaticBackups []BackupSingle
}

// BackupSingle is the information we want to dump from a lnd channel backup.
// See `chanbackup.Single` for information about the fields.
type BackupSingle struct {
	Version          chanbackup.SingleBackupVersion
	IsInitiator      bool
	ChainHash        string
	FundingOutpoint  string
	ShortChannelID   lnwire.ShortChannelID
	RemoteNodePub    string
	Addresses        []net.Addr
	Capacity         btcutil.Amount
	LocalChanCfg     ChannelConfig
	RemoteChanCfg    ChannelConfig
	ShaChainRootDesc KeyDescriptor
	CloseTxInputs    *CloseTxInputs
}

// CloseTxInputs is a struct that contains data needed to produce a force close
// transaction from a channel backup as a last resort recovery method.
type CloseTxInputs struct {
	CommitTx      string
	CommitSig     string
	CommitHeight  uint64
	TapscriptRoot string
}

// OpenChannel is the information we want to dump from an open channel in lnd's
// channel DB. See `channeldb.OpenChannel` for information about the fields.
type OpenChannel struct {
	ChanType                channeldb.ChannelType
	ChainHash               chainhash.Hash
	FundingOutpoint         string
	ShortChannelID          lnwire.ShortChannelID
	IsPending               bool
	IsInitiator             bool
	ChanStatus              channeldb.ChannelStatus
	FundingBroadcastHeight  uint32
	NumConfsRequired        uint16
	ChannelFlags            lnwire.FundingFlag
	ThawHeight              uint32
	IdentityPub             string
	Capacity                btcutil.Amount
	TotalMSatSent           lnwire.MilliSatoshi
	TotalMSatReceived       lnwire.MilliSatoshi
	PerCommitPoint          string
	LocalChanCfg            ChannelConfig
	RemoteChanCfg           ChannelConfig
	LocalCommitment         channeldb.ChannelCommitment
	RemoteCommitment        channeldb.ChannelCommitment
	LocalCommitmentDebug    ChannelDebugInfo
	RemoteCommitmentDebug   ChannelDebugInfo
	RemoteCurrentRevocation string
	RemoteNextRevocation    string
	FundingTxn              string
	LocalShutdownScript     lnwire.DeliveryAddress
	RemoteShutdownScript    lnwire.DeliveryAddress
}

// ChannelDebugInfo is a struct that holds additional information about an open
// or pending channel that is useful for debugging.
type ChannelDebugInfo struct {
	ToLocalScript  string
	ToLocalAddr    string
	ToRemoteScript string
	ToRemoteAddr   string
}

// ClosedChannel is the information we want to dump from a closed channel in
// lnd's channel DB. See `channeldb.ChannelCloseSummary` for information about
// the fields.
type ClosedChannel struct {
	ChanPoint                 string
	ShortChanID               lnwire.ShortChannelID
	ChainHash                 chainhash.Hash
	ClosingTXID               string
	RemotePub                 string
	Capacity                  btcutil.Amount
	CloseHeight               uint32
	SettledBalance            btcutil.Amount
	TimeLockedBalance         btcutil.Amount
	CloseType                 string
	IsPending                 bool
	RemoteCurrentRevocation   string
	RemoteNextRevocation      string
	LocalChanConfig           ChannelConfig
	NextLocalCommitHeight     uint64
	RemoteCommitTailHeight    uint64
	LastRemoteCommitSecret    string
	LocalUnrevokedCommitPoint string
	HistoricalChannel         *OpenChannel
}

// ChannelConfig is the information we want to dump from a channel
// configuration. See `channeldb.ChannelConfig` for more information about the
// fields.
type ChannelConfig struct {
	channeldb.ChannelStateBounds

	channeldb.CommitmentParams

	MultiSigKey         KeyDescriptor
	RevocationBasePoint KeyDescriptor
	PaymentBasePoint    KeyDescriptor
	DelayBasePoint      KeyDescriptor
	HtlcBasePoint       KeyDescriptor
}

// KeyDescriptor is the information we want to dump from a key descriptor. See
// `keychain.KeyDescriptor` for more information about the fields.
type KeyDescriptor struct {
	Path   string
	PubKey string
}

// OpenChannelDump converts the open channels in the given channel DB into a
// dumpable format.
func OpenChannelDump(channels []*channeldb.OpenChannel,
	params *chaincfg.Params) ([]OpenChannel, error) {

	dumpChannels := make([]OpenChannel, len(channels))
	for idx, channel := range channels {
		openChan, err := openChannelDump(channel, params)
		if err != nil {
			return nil, fmt.Errorf("error converting to dump "+
				"format: %w", err)
		}
		dumpChannels[idx] = *openChan
	}
	return dumpChannels, nil
}

func openChannelDump(channel *channeldb.OpenChannel,
	params *chaincfg.Params) (*OpenChannel, error) {

	var buf bytes.Buffer
	if channel.FundingTxn != nil {
		err := channel.FundingTxn.Serialize(&buf)
		if err != nil {
			return nil, err
		}
	}
	revPreimage, err := channel.RevocationProducer.AtIndex(
		channel.LocalCommitment.CommitHeight,
	)
	if err != nil {
		return nil, err
	}
	perCommitPoint := input.ComputeCommitmentPoint(revPreimage[:])

	openChan := &OpenChannel{
		ChanType:               channel.ChanType,
		ChainHash:              channel.ChainHash,
		FundingOutpoint:        channel.FundingOutpoint.String(),
		ShortChannelID:         channel.ShortChannelID,
		IsPending:              channel.IsPending,
		IsInitiator:            channel.IsInitiator,
		ChanStatus:             channel.ChanStatus(),
		FundingBroadcastHeight: channel.FundingBroadcastHeight,
		NumConfsRequired:       channel.NumConfsRequired,
		ChannelFlags:           channel.ChannelFlags,
		ThawHeight:             channel.ThawHeight,
		IdentityPub: PubKeyToString(
			channel.IdentityPub,
		),
		Capacity:          channel.Capacity,
		TotalMSatSent:     channel.TotalMSatSent,
		TotalMSatReceived: channel.TotalMSatReceived,
		PerCommitPoint:    PubKeyToString(perCommitPoint),
		LocalChanCfg: ToChannelConfig(
			params, channel.LocalChanCfg,
		),
		RemoteChanCfg: ToChannelConfig(
			params, channel.RemoteChanCfg,
		),
		LocalCommitment:  channel.LocalCommitment,
		RemoteCommitment: channel.RemoteCommitment,
		RemoteCurrentRevocation: PubKeyToString(
			channel.RemoteCurrentRevocation,
		),
		RemoteNextRevocation: PubKeyToString(
			channel.RemoteNextRevocation,
		),
		FundingTxn:           hex.EncodeToString(buf.Bytes()),
		LocalShutdownScript:  channel.LocalShutdownScript,
		RemoteShutdownScript: channel.RemoteShutdownScript,
	}

	localDebug, err := CollectDebugInfo(
		channel, perCommitPoint, true, channel.IsInitiator, params,
	)
	if err != nil {
		return nil, fmt.Errorf("error collecting local debug info: %w",
			err)
	}

	remoteDebug, err := CollectDebugInfo(
		channel, channel.RemoteCurrentRevocation, false,
		!channel.IsInitiator, params,
	)
	if err != nil {
		return nil, fmt.Errorf("error collecting remote debug info: %w",
			err)
	}

	openChan.LocalCommitmentDebug = *localDebug
	openChan.RemoteCommitmentDebug = *remoteDebug

	return openChan, nil
}

// CollectDebugInfo collects the additional debug information for the given
// channel.
func CollectDebugInfo(channel *channeldb.OpenChannel,
	commitPoint *btcec.PublicKey, ourCommit, initiator bool,
	params *chaincfg.Params) (*ChannelDebugInfo, error) {

	chanType := channel.ChanType
	ourChanCfg := &channel.LocalChanCfg
	theirChanCfg := &channel.RemoteChanCfg
	leaseExpiry := channel.ThawHeight

	var whoseCommit lntypes.ChannelParty
	if ourCommit {
		whoseCommit = lntypes.Local
	} else {
		whoseCommit = lntypes.Remote
	}

	keyRing := lnwallet.DeriveCommitmentKeys(
		commitPoint, whoseCommit, chanType, ourChanCfg, theirChanCfg,
	)

	// FIXME: fill auxLeaf for Tapscript root channels.
	var auxLeaf input.AuxTapLeaf

	// First, we create the script for the delayed "pay-to-self" output.
	// This output has 2 main redemption clauses: either we can redeem the
	// output after a relative block delay, or the remote node can claim
	// the funds with the revocation key if we broadcast a revoked
	// commitment transaction.
	toLocalScript, err := lnwallet.CommitScriptToSelf(
		chanType, initiator, keyRing.ToLocalKey, keyRing.RevocationKey,
		uint32(ourChanCfg.CsvDelay), leaseExpiry, auxLeaf,
	)
	if err != nil {
		return nil, err
	}

	// Next, we create the script paying to the remote.
	toRemoteScript, _, err := lnwallet.CommitScriptToRemote(
		chanType, initiator, keyRing.ToRemoteKey, leaseExpiry, auxLeaf,
	)
	if err != nil {
		return nil, err
	}

	toLocalPkScript, err := txscript.ParsePkScript(toLocalScript.PkScript())
	if err != nil {
		return nil, err
	}
	toLocalAddr, err := toLocalPkScript.Address(params)
	if err != nil {
		return nil, err
	}

	toRemotePkScript, err := txscript.ParsePkScript(
		toRemoteScript.PkScript(),
	)
	if err != nil {
		return nil, err
	}
	toRemoteAddr, err := toRemotePkScript.Address(params)
	if err != nil {
		return nil, err
	}

	return &ChannelDebugInfo{
		ToLocalScript: hex.EncodeToString(
			toLocalScript.WitnessScriptToSign(),
		),
		ToLocalAddr: toLocalAddr.String(),
		ToRemoteScript: hex.EncodeToString(
			toRemoteScript.WitnessScriptToSign(),
		),
		ToRemoteAddr: toRemoteAddr.String(),
	}, nil
}

// ClosedChannelDump converts the closed channels in the given channel DB into a
// dumpable format.
func ClosedChannelDump(channels []*channeldb.ChannelCloseSummary,
	historicalChannels []*channeldb.OpenChannel,
	params *chaincfg.Params) ([]ClosedChannel, error) {

	dumpChannels := make([]ClosedChannel, len(channels))
	for idx, channel := range channels {
		var (
			nextLocalHeight, remoteTailHeight uint64
			lastRemoteSecret                  string
			localUnrevokedCommitPoint         *btcec.PublicKey
			historicalChannel                 *OpenChannel
		)

		if channel.LastChanSyncMsg != nil {
			msg := channel.LastChanSyncMsg
			nextLocalHeight = msg.NextLocalCommitHeight
			remoteTailHeight = msg.RemoteCommitTailHeight
			lastRemoteSecret = hex.EncodeToString(
				msg.LastRemoteCommitSecret[:],
			)
			localUnrevokedCommitPoint = msg.LocalUnrevokedCommitPoint
		}

		histChan := historicalChannels[idx]
		if histChan != nil {
			openChan, err := openChannelDump(histChan, params)
			if err != nil {
				return nil, fmt.Errorf("error converting to "+
					"dump format: %w", err)
			}
			historicalChannel = openChan
		}

		dumpChannels[idx] = ClosedChannel{
			ChanPoint:         channel.ChanPoint.String(),
			ShortChanID:       channel.ShortChanID,
			ChainHash:         channel.ChainHash,
			ClosingTXID:       channel.ClosingTXID.String(),
			RemotePub:         PubKeyToString(channel.RemotePub),
			Capacity:          channel.Capacity,
			CloseHeight:       channel.CloseHeight,
			SettledBalance:    channel.SettledBalance,
			TimeLockedBalance: channel.TimeLockedBalance,
			CloseType: fmt.Sprintf(
				"%d", channel.CloseType,
			),
			IsPending: channel.IsPending,
			RemoteCurrentRevocation: PubKeyToString(
				channel.RemoteCurrentRevocation,
			),
			RemoteNextRevocation: PubKeyToString(
				channel.RemoteNextRevocation,
			),
			LocalChanConfig: ToChannelConfig(
				params, channel.LocalChanConfig,
			),
			NextLocalCommitHeight:  nextLocalHeight,
			RemoteCommitTailHeight: remoteTailHeight,
			LastRemoteCommitSecret: lastRemoteSecret,
			LocalUnrevokedCommitPoint: PubKeyToString(
				localUnrevokedCommitPoint,
			),
			HistoricalChannel: historicalChannel,
		}
	}
	return dumpChannels, nil
}

// BackupDump converts the given multi backup into a dumpable format.
func BackupDump(multi *chanbackup.Multi,
	params *chaincfg.Params) []BackupSingle {

	dumpSingles := make([]BackupSingle, len(multi.StaticBackups))
	for idx, single := range multi.StaticBackups {
		dumpSingles[idx] = BackupSingle{
			Version:         single.Version,
			IsInitiator:     single.IsInitiator,
			ChainHash:       single.ChainHash.String(),
			FundingOutpoint: single.FundingOutpoint.String(),
			ShortChannelID:  single.ShortChannelID,
			RemoteNodePub: PubKeyToString(
				single.RemoteNodePub,
			),
			Addresses: single.Addresses,
			Capacity:  single.Capacity,
			LocalChanCfg: ToChannelConfig(
				params, single.LocalChanCfg,
			),
			RemoteChanCfg: ToChannelConfig(
				params, single.RemoteChanCfg,
			),
			ShaChainRootDesc: ToKeyDescriptor(
				params, single.ShaChainRootDesc,
			),
		}

		single.CloseTxInputs.WhenSome(
			func(inputs chanbackup.CloseTxInputs) {
				// Serialize unsigned transaction.
				var buf bytes.Buffer
				err := inputs.CommitTx.Serialize(&buf)
				if err != nil {
					buf.WriteString("error serializing " +
						"commit tx: " + err.Error())
				}
				tx := buf.Bytes()

				// Serialize TapscriptRoot if present.
				var tapscriptRoot string
				inputs.TapscriptRoot.WhenSome(
					func(tr chainhash.Hash) {
						tapscriptRoot = tr.String()
					},
				)

				// Put all CloseTxInputs to dump in human
				// readable form.
				dumpSingles[idx].CloseTxInputs = &CloseTxInputs{
					CommitTx: hex.EncodeToString(tx),
					CommitSig: hex.EncodeToString(
						inputs.CommitSig,
					),
					CommitHeight:  inputs.CommitHeight,
					TapscriptRoot: tapscriptRoot,
				}
			},
		)
	}

	return dumpSingles
}

func ToChannelConfig(params *chaincfg.Params,
	cfg channeldb.ChannelConfig) ChannelConfig {

	return ChannelConfig{
		ChannelStateBounds: cfg.ChannelStateBounds,
		CommitmentParams:   cfg.CommitmentParams,
		MultiSigKey:        ToKeyDescriptor(params, cfg.MultiSigKey),
		RevocationBasePoint: ToKeyDescriptor(
			params, cfg.RevocationBasePoint,
		),
		PaymentBasePoint: ToKeyDescriptor(
			params, cfg.PaymentBasePoint,
		),
		DelayBasePoint: ToKeyDescriptor(
			params, cfg.DelayBasePoint,
		),
		HtlcBasePoint: ToKeyDescriptor(params, cfg.HtlcBasePoint),
	}
}

func ToKeyDescriptor(params *chaincfg.Params,
	desc keychain.KeyDescriptor) KeyDescriptor {

	return KeyDescriptor{
		Path: fmt.Sprintf(
			lndInternalDerivationPath, params.HDCoinType,
			desc.Family, desc.Index,
		),
		PubKey: PubKeyToString(desc.PubKey),
	}
}

func PubKeyToString(pubkey *btcec.PublicKey) string {
	if pubkey == nil {
		return "<nil>"
	}
	return hex.EncodeToString(pubkey.SerializeCompressed())
}
