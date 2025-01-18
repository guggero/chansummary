package main

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	"github.com/davecgh/go-spew/spew"
	"github.com/lightninglabs/chantools/dump"
	"github.com/lightninglabs/chantools/lnd"
	"github.com/lightningnetwork/lnd/channeldb"
	"github.com/lightningnetwork/lnd/lnrpc"
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

func dumphistoricalchan() *cobra.Command {
	cc := &summaryHTLC{}
	cc.cmd = &cobra.Command{
		Use: "dumphistoricalchannel",
		Short: "dump all information of a closed channel's last " +
			"commitment state",
		Long: `when a channel is closed we delete all the data from the
			openchannel bkt and move the last commitment state to
			the historical bkt. This command aims to dump all the
			necessary data from that last state.`,
		Example: `chantools dumphtlcsummary \
	--channeldb ~/.lnd/data/graph/mainnet/channel.db`,
		RunE: cc.Execute,
	}
	cc.cmd.Flags().StringVar(
		&cc.ChannelDB, "channeldb", "", "lnd channel.db file to dump "+
			"channels from",
	)
	cc.cmd.Flags().StringVar(
		&cc.ChannelPoint, "chan_point", "", "",
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

	return dumpHistoricalChanInfos(db.ChannelStateDB(), c.ChannelPoint)
}

func dumpHistoricalChanInfos(chanDb *channeldb.ChannelStateDB, channel string) error {

	chanPoint, err := parseChanPoint(channel)
	if err != nil {
		return err
	}

	//Open the Historical Bucket
	fundingHash, err := chainhash.NewHash(chanPoint.GetFundingTxidBytes())

	fmt.Println("Test", fundingHash.String())

	if err != nil {
		return err
	}
	outPoint := wire.NewOutPoint(fundingHash, chanPoint.OutputIndex)

	dbChannel, err := chanDb.FetchHistoricalChannel(outPoint)
	if err != nil {
		return err
	}

	channels := []*channeldb.OpenChannel{
		dbChannel,
	}

	dumpChannels, err := dump.OpenChannelDump(channels, chainParams)
	if err != nil {
		return fmt.Errorf("error converting to dump format: %w", err)
	}

	spew.Dump(dumpChannels)

	// For the tests, also log as trace level which is disabled by default.
	log.Tracef(spew.Sdump(dumpChannels))

	// Go also through all the HTLCs and calculate the sha of the onionblob.
	log.Debug("===========================================================")
	local := dbChannel.LocalCommitment
	remote := dbChannel.RemoteCommitment
	log.Debugf("RemoteCommitment: height=%v", remote.CommitHeight)
	log.Debugf("LocalCommitment: height=%v", local.CommitHeight)

	remoteHtlcs := make(map[[32]byte]struct{})
	for _, htlc := range remote.Htlcs {
		log.Debugf("RemoteCommitment has htlc: id=%v, update=%v "+
			"incoming=%v", htlc.HtlcIndex, htlc.LogIndex,
			htlc.Incoming)

		onionHash := sha256.Sum256(htlc.OnionBlob[:])
		remoteHtlcs[onionHash] = struct{}{}

	}

	// as active if *we* know them as well.
	activeHtlcs := make([]channeldb.HTLC, 0, len(remoteHtlcs))
	for _, htlc := range local.Htlcs {
		log.Debugf("LocalCommitment has htlc: id=%v, update=%v "+
			"incoming=%v", htlc.HtlcIndex, htlc.LogIndex,
			htlc.Incoming)

		onionHash := sha256.Sum256(htlc.OnionBlob[:])
		if _, ok := remoteHtlcs[onionHash]; !ok {
			log.Debugf("Skipped htlc due to onion has not "+
				"matched: id=%v, update=%v incoming=%v",
				htlc.HtlcIndex, htlc.LogIndex, htlc.Incoming)

			continue
		}
		activeHtlcs = append(activeHtlcs, htlc)
	}

	log.Debugf("Active htlcs on the local commitment when the channel " +
		"closed")

	spew.Dump(activeHtlcs)

	return nil
}
