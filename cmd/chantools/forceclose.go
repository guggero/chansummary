package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/btcsuite/btcd/btcutil/hdkeychain"
	"github.com/btcsuite/btcd/txscript"
	"github.com/lightninglabs/chantools/dataformat"
	"github.com/lightninglabs/chantools/lnd"
	"github.com/lightningnetwork/lnd/channeldb"
	"github.com/lightningnetwork/lnd/input"
	"github.com/spf13/cobra"
)

const forceCloseWarning = `
If you are certain that a node is offline for good (AFTER you've tried SCB!)
and a channel is still open, you can use this method to force-close your
latest state that you have in your channel.db.

**!!! WARNING !!! DANGER !!! WARNING !!!**

If you do this and the state that you publish is *not* the latest state, then
the remote node *could* punish you by taking the whole channel amount *if* they
come online before you can sweep the funds from the time locked (144 - 2000
blocks) transaction *or* they have a watch tower looking out for them.

**This should absolutely be the last resort and you have been warned!**`

type forceCloseCommand struct {
	APIURL    string
	ChannelDB string
	Publish   bool

	rootKey *rootKey
	inputs  *inputFlags
	cmd     *cobra.Command
}

func newForceCloseCommand() *cobra.Command {
	cc := &forceCloseCommand{}
	cc.cmd = &cobra.Command{
		Use: "forceclose",
		Short: "Force-close the last state that is in the channel.db " +
			"provided",
		Long: forceCloseWarning,
		Example: `chantools forceclose \
	--fromsummary results/summary-xxxx-yyyy.json
	--channeldb ~/.lnd/data/graph/mainnet/channel.db \
	--publish`,
		RunE: cc.Execute,
	}
	cc.cmd.Flags().StringVar(
		&cc.APIURL, "apiurl", defaultAPIURL, "API URL to use (must "+
			"be esplora compatible)",
	)
	cc.cmd.Flags().StringVar(
		&cc.ChannelDB, "channeldb", "", "lnd channel.db file to use "+
			"for force-closing channels",
	)
	cc.cmd.Flags().BoolVar(
		&cc.Publish, "publish", false, "publish force-closing TX to "+
			"the chain API instead of just printing the TX",
	)

	cc.rootKey = newRootKey(cc.cmd, "decrypting the backup")
	cc.inputs = newInputFlags(cc.cmd)

	return cc.cmd
}

func (c *forceCloseCommand) Execute(_ *cobra.Command, _ []string) error {
	extendedKey, err := c.rootKey.read()
	if err != nil {
		return fmt.Errorf("error reading root key: %w", err)
	}

	// Check that we have a channel DB.
	if c.ChannelDB == "" {
		return errors.New("rescue DB is required")
	}
	db, err := lnd.OpenDB(c.ChannelDB, true)
	if err != nil {
		return fmt.Errorf("error opening rescue DB: %w", err)
	}

	// Parse channel entries from any of the possible input files.
	entries, err := c.inputs.parseInputType()
	if err != nil {
		return err
	}
	return forceCloseChannels(
		c.APIURL, extendedKey, entries, db.ChannelStateDB(), c.Publish,
	)
}

func forceCloseChannels(apiURL string, extendedKey *hdkeychain.ExtendedKey,
	entries []*dataformat.SummaryEntry, chanDb *channeldb.ChannelStateDB,
	publish bool) error {

	channels, err := chanDb.FetchAllChannels()
	if err != nil {
		return err
	}
	api := newExplorerAPI(apiURL)
	signer := &lnd.Signer{
		ExtendedKey: extendedKey,
		ChainParams: chainParams,
	}

	// Go through all channels in the DB, find the still open ones and
	// publish their local commitment TX.
	for _, channel := range channels {
		channelPoint := channel.FundingOutpoint.String()
		var channelEntry *dataformat.SummaryEntry
		for _, entry := range entries {
			if entry.ChannelPoint == channelPoint {
				channelEntry = entry
			}
		}

		// Don't try anything with closed channels.
		if channelEntry == nil || channelEntry.ClosingTX != nil {
			continue
		}

		localCommit := channel.LocalCommitment
		localCommitTx := localCommit.CommitTx
		if localCommitTx == nil {
			log.Errorf("Cannot force-close, no local commit TX "+
				"for channel %s", channelEntry.ChannelPoint)

			continue
		}

		// Create signed transaction.
		lc := &lnd.LightningChannel{
			LocalChanCfg:  channel.LocalChanCfg,
			RemoteChanCfg: channel.RemoteChanCfg,
			ChannelState:  channel,
			TXSigner:      signer,
		}
		err := lc.CreateSignDesc()
		if err != nil {
			return err
		}

		// Serialize transaction.
		signedTx, err := lc.SignedCommitTx()
		if err != nil {
			return err
		}
		var buf bytes.Buffer
		err = signedTx.Serialize(io.Writer(&buf))
		if err != nil {
			return err
		}
		hash := signedTx.TxHash()
		serialized := hex.EncodeToString(buf.Bytes())

		// Calculate commit point.
		basepoint := channel.LocalChanCfg.DelayBasePoint
		revpoint := channel.RemoteChanCfg.RevocationBasePoint
		revocationPreimage, err := channel.RevocationProducer.AtIndex(
			localCommit.CommitHeight,
		)
		if err != nil {
			return err
		}
		point := input.ComputeCommitmentPoint(revocationPreimage[:])

		// Store all information that we collected into the channel
		// entry file so we don't need to use the channel.db file for
		// the next step.
		channelEntry.ForceClose = &dataformat.ForceClose{
			TXID:       hash.String(),
			Serialized: serialized,
			DelayBasePoint: &dataformat.BasePoint{
				Family: uint16(basepoint.Family),
				Index:  basepoint.Index,
				PubKey: hex.EncodeToString(
					basepoint.PubKey.SerializeCompressed(),
				),
			},
			RevocationBasePoint: &dataformat.BasePoint{
				PubKey: hex.EncodeToString(
					revpoint.PubKey.SerializeCompressed(),
				),
			},
			CommitPoint: hex.EncodeToString(
				point.SerializeCompressed(),
			),
			Outs: make(
				[]*dataformat.Out, len(localCommitTx.TxOut),
			),
			CSVDelay: channel.LocalChanCfg.CsvDelay,
		}
		for idx, out := range localCommitTx.TxOut {
			script, err := txscript.DisasmString(out.PkScript)
			if err != nil {
				return err
			}
			channelEntry.ForceClose.Outs[idx] = &dataformat.Out{
				Script:    hex.EncodeToString(out.PkScript),
				ScriptAsm: script,
				Value:     uint64(out.Value),
			}
		}

		// Publish TX.
		if publish {
			response, err := api.PublishTx(serialized)
			if err != nil {
				return err
			}
			log.Infof("Published TX %s, response: %s",
				hash.String(), response)
		}
	}

	summaryBytes, err := json.MarshalIndent(&dataformat.SummaryEntryFile{
		Channels: entries,
	}, "", " ")
	if err != nil {
		return err
	}
	fileName := fmt.Sprintf("results/forceclose-%s.json",
		time.Now().Format("2006-01-02-15-04-05"))
	log.Infof("Writing result to %s", fileName)
	return os.WriteFile(fileName, summaryBytes, 0644)
}
