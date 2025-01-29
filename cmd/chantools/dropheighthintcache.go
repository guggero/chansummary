package main

import (
	"bytes"
	"fmt"
	"strconv"
	"strings"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/lightninglabs/chantools/btc"
	"github.com/lightninglabs/chantools/lnd"
	"github.com/lightningnetwork/lnd/chainntnfs"
	"github.com/lightningnetwork/lnd/channeldb"
	"github.com/lightningnetwork/lnd/kvdb"
	"github.com/spf13/cobra"
)

var spendHintBucket = []byte("spend-hints")

type dropHeightHintCacheCommand struct {
	APIURL    string
	ChannelDB string
	ChanPoint string

	cmd *cobra.Command
}

func newDropHeightHintCacheCommand() *cobra.Command {
	cc := &dropHeightHintCacheCommand{}
	cc.cmd = &cobra.Command{
		Use:   "dropheighthintcache",
		Short: "Remove all height hints used for spend notifications",
		Long: `Removes either all spent height hint entries for
channels remaining in the __waiting_force_close__ state or for an explicit 
outpoint which leads to an internal rescan resolving all contracts already due.`,
		Example: `chantools dropheighthintcache \
	--channeldb ~/.lnd/data/graph/mainnet/channel.db \
	-chan_point bd278162f98...ecbab00764c8a1:0`,
		RunE: cc.Execute,
	}
	cc.cmd.Flags().StringVar(
		&cc.ChannelDB, "channeldb", "", "lnd channel.db file to dump "+
			"channels from",
	)
	cc.cmd.Flags().StringVar(
		&cc.ChanPoint, "chan_point", "", "outpoint for which the "+
			"height should be removed ",
	)
	cc.cmd.Flags().StringVar(
		&cc.APIURL, "apiurl", defaultAPIURL, "API URL to use (must "+
			"be esplora compatible)",
	)
	return cc.cmd
}

func (c *dropHeightHintCacheCommand) Execute(_ *cobra.Command, _ []string) error {
	if c.ChannelDB == "" {
		return fmt.Errorf("channel DB is required")
	}

	db, err := lnd.OpenDB(c.ChannelDB, false)
	if err != nil {
		return fmt.Errorf("error opening rescue DB: %w", err)
	}
	defer func() { _ = db.Close() }()

	if c.ChanPoint != "" {
		return dropHeightHintOutpoint(db, c.ChanPoint, c.APIURL)
	}

	// In case no channel point is selected we will only remove the spent
	// hint for channels which are borked and in the state
	// __waiting_close__ (fundingTx not yet confirmed).
	err = dropHeightHintFundingTx(db)
	if err != nil {
		return err
	}

	return nil
}

// dropHeightHintFundingTx queries the underlying channel.db for channels which
// are in the __waiting_close_channels__ bucket. This means the channel is
// already borked but the funding tx has still not been spent. We observed in
// some cases that the relevant height hint cache was poisoned leading to an
// unrecognized closed channel. Deleting the underlying height hint should
// tigger a rescan form an earlier blockheight and therefore finding the
// confirmed fundingTx.
func dropHeightHintFundingTx(db *channeldb.DB) error {
	// We only fetch the waiting force close channels.
	channels, err := db.ChannelStateDB().FetchWaitingCloseChannels()
	if err != nil {
		return err
	}

	spendRequests := make([]*chainntnfs.SpendRequest, 0, len(channels))

	for _, channel := range channels {
		spendRequests = append(spendRequests, &chainntnfs.SpendRequest{
			OutPoint: channel.FundingOutpoint,
			// We index the SpendRequest entry in the db by the
			// outpoint value (for the channel close observer at
			// least).
			PkScript: txscript.PkScript{},
		})
	}

	// We resolve all the waiting force close channels which might have
	// a poisoned height hint cache.
	return kvdb.Batch(db.Backend, func(tx kvdb.RwTx) error {
		spendHints := tx.ReadWriteBucket(spendHintBucket)
		if spendHints == nil {
			return chainntnfs.ErrCorruptedHeightHintCache
		}

		for _, request := range spendRequests {
			var outpoint bytes.Buffer
			err := channeldb.WriteElement(
				&outpoint, request.OutPoint,
			)
			if err != nil {
				return err
			}

			spendKey := outpoint.Bytes()
			if err := spendHints.Delete(spendKey); err != nil {
				log.Debugf("outpoint not found in the height "+
					"hint cache: "+
					"%v", request.OutPoint.String())

				return err
			}
			log.Infof("deleted height hint for outpoint: "+
				"%v \n", request.OutPoint.String())
		}

		return nil
	})
}

// dropHeightHintOutpoint deletes the height hint cache for a specific outpoint.
// Sometimes a channel is stuck in a pending state because the spend of a
// channel contract was not recognized. In other words the height hint cache
// for this outpoint was poisoned and we need to delete its value so we trigger
// a clean rescan from the initial height of the channel contract.
func dropHeightHintOutpoint(db *channeldb.DB, chanPoint, apiURL string) error {
	api := &btc.ExplorerAPI{BaseURL: apiURL}
	// Check that the outpoint is really spent
	addr, err := api.Address(chanPoint)
	if err != nil {
		return err
	}
	spends, err := api.Spends(addr)
	if err != nil || len(spends) == 0 {
		return fmt.Errorf("outpoint is not spend yet")
	}
	outPoint, err := parseChanPoint(chanPoint)
	if err != nil {
		return err
	}

	return kvdb.Update(db.Backend, func(tx kvdb.RwTx) error {
		spendHints := tx.ReadWriteBucket(spendHintBucket)
		if spendHints == nil {
			return chainntnfs.ErrCorruptedHeightHintCache
		}

		var outPointBytes bytes.Buffer
		err := channeldb.WriteElement(
			&outPointBytes, outPoint,
		)
		if err != nil {
			return err
		}

		spendKey := outPointBytes.Bytes()
		if err := spendHints.Delete(spendKey); err != nil {
			log.Debugf("outpoint not found in the height "+
				"hint cache: "+
				"%v", outPoint.String())

			return err
		}
		log.Infof("deleted height hint for outpoint: "+
			"%v \n", outPoint.String())

		return nil
	}, func() {})
}

func parseChanPoint(s string) (*wire.OutPoint, error) {
	split := strings.Split(s, ":")
	if len(split) != 2 || len(split[0]) == 0 || len(split[1]) == 0 {
		return nil, fmt.Errorf("invalid channel point")
	}

	index, err := strconv.ParseInt(split[1], 10, 64)
	if err != nil {
		return nil, fmt.Errorf("unable to decode output index: %w", err)
	}

	txid, err := chainhash.NewHashFromStr(split[0])
	if err != nil {
		return nil, fmt.Errorf("unable to parse hex string: %w", err)
	}

	return &wire.OutPoint{Hash: *txid,
		Index: uint32(index)}, nil
}
