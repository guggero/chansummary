package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	"github.com/lightninglabs/chantools/lnd"
	"github.com/lightningnetwork/lnd/channeldb"
	"github.com/lightningnetwork/lnd/input"
	"github.com/lightningnetwork/lnd/lnrpc"
	"github.com/lightningnetwork/lnd/lnwallet"
	"github.com/spf13/cobra"
)

type summaryHTLC struct {
	ChannelDB    string
	ChannelPoint string

	rootKey *rootKey
	cmd     *cobra.Command
}

var errBadChanPoint = errors.New("expecting chan_point to be in format of: " +
	"txid:index")

func parseChanPoint(s string) (*lnrpc.ChannelPoint, error) {
	split := strings.Split(s, ":")
	if len(split) != 2 || len(split[0]) == 0 || len(split[1]) == 0 {
		return nil, errBadChanPoint
	}

	index, err := strconv.ParseInt(split[1], 10, 64)
	if err != nil {
		return nil, fmt.Errorf("unable to decode output index: %v", err)
	}

	txid, err := chainhash.NewHashFromStr(split[0])
	if err != nil {
		return nil, fmt.Errorf("unable to parse hex string: %v", err)
	}

	return &lnrpc.ChannelPoint{
		FundingTxid: &lnrpc.ChannelPoint_FundingTxidBytes{
			FundingTxidBytes: txid[:],
		},
		OutputIndex: uint32(index),
	}, nil
}

func dumphtlcsummary() *cobra.Command {
	cc := &summaryHTLC{}
	cc.cmd = &cobra.Command{
		Use: "dumphtlcsummary",
		Short: "dump all the necessary htlc information which are " +
			"needed for the peer to recover his funds",
		Long: `...`,
		Example: `chantools dumphtlcsummary \
	--channeldb ~/.lnd/data/graph/mainnet/channel.db`,
		RunE: cc.Execute,
	}
	cc.cmd.Flags().StringVar(
		&cc.ChannelDB, "channeldb", "", "lnd channel.db file to dump "+
			"channels from",
	)
	cc.cmd.Flags().StringVar(
		&cc.ChannelPoint, "ChannelPoint", "", "",
	)

	cc.rootKey = newRootKey(cc.cmd, "deriving keys")

	return cc.cmd
}

func (c *summaryHTLC) Execute(_ *cobra.Command, _ []string) error {
	// Check that we have a channel DB.
	if c.ChannelDB == "" {
		return fmt.Errorf("channel DB is required")
	}
	db, err := lnd.OpenDB(c.ChannelDB, true)
	if err != nil {
		return fmt.Errorf("error opening rescue DB: %w", err)
	}
	defer func() { _ = db.Close() }()

	return dumpHtlcInfos(db.ChannelStateDB(), c.ChannelPoint)
}

type hltcInfo struct {
	HtlcAddress         string
	WitnessScript       string
	CommitPoint         string
	LocalHTLCBasePoint  string
	RemoteHTLCBasePoint string
	RemoteHTLCPubkey    string
	LocalHTLCPubkey     string
}

func dumpHtlcInfos(chanDb *channeldb.ChannelStateDB, channel string) error {

	var htlcs []hltcInfo

	chanPoint, err := parseChanPoint(channel)
	if err != nil {
		return err
	}

	//Open the Historical Bucket
	fundingHash, err := chainhash.NewHash(chanPoint.GetFundingTxidBytes())

	if err != nil {
		return err
	}
	outPoint := wire.NewOutPoint(fundingHash, chanPoint.OutputIndex)

	dbChannel, err := chanDb.FetchHistoricalChannel(outPoint)
	if err != nil {
		return err
	}

	fmt.Println(dbChannel.ChanType.IsTweakless())

	for _, htlc := range dbChannel.LocalCommitment.Htlcs {
		// Only Incoming HTLCs for now.
		if !htlc.Incoming {
			continue
		}

		revocationPreimage, err := dbChannel.RevocationProducer.AtIndex(
			dbChannel.LocalCommitment.CommitHeight,
		)
		if err != nil {
			return err
		}
		localCommitPoint := input.ComputeCommitmentPoint(revocationPreimage[:])

		keyRing := lnwallet.DeriveCommitmentKeys(
			localCommitPoint, true, dbChannel.ChanType,
			&dbChannel.LocalChanCfg,
			&dbChannel.RemoteChanCfg,
		)

		witnessScript, err := input.ReceiverHTLCScript(
			htlc.RefundTimeout, keyRing.RemoteHtlcKey, keyRing.LocalHtlcKey,
			keyRing.RevocationKey, htlc.RHash[:], dbChannel.ChanType.HasAnchors(),
		)
		witnessScriptHash := sha256.Sum256(witnessScript)
		htlcAddr, err := btcutil.NewAddressWitnessScriptHash(
			witnessScriptHash[:], chainParams,
		)

		htlcs = append(htlcs, hltcInfo{
			HtlcAddress:         htlcAddr.String(),
			WitnessScript:       hex.EncodeToString(witnessScript),
			CommitPoint:         hex.EncodeToString(localCommitPoint.SerializeCompressed()),
			LocalHTLCBasePoint:  hex.EncodeToString(dbChannel.LocalChanCfg.HtlcBasePoint.PubKey.SerializeCompressed()),
			RemoteHTLCBasePoint: hex.EncodeToString(dbChannel.RemoteChanCfg.HtlcBasePoint.PubKey.SerializeCompressed()),
			LocalHTLCPubkey:     hex.EncodeToString(keyRing.LocalHtlcKey.SerializeCompressed()),
			RemoteHTLCPubkey:    hex.EncodeToString(keyRing.RemoteHtlcKey.SerializeCompressed()),
		})
	}

	data, err := json.MarshalIndent(htlcs, "", "  ")

	fmt.Printf("%v", string(data))

	return nil

}
