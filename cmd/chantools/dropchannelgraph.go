package main

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/wire"
	"github.com/lightninglabs/chantools/lnd"
	"github.com/lightningnetwork/lnd/chainreg"
	"github.com/lightningnetwork/lnd/channeldb"
	"github.com/lightningnetwork/lnd/channeldb/models"
	"github.com/lightningnetwork/lnd/keychain"
	"github.com/lightningnetwork/lnd/lnwire"
	"github.com/spf13/cobra"
)

var (
	nodeBucket      = []byte("graph-node")
	edgeBucket      = []byte("graph-edge")
	graphMetaBucket = []byte("graph-meta")
)

type dropChannelGraphCommand struct {
	ChannelDB       string
	NodeIdentityKey string
	FixOnly         bool

	SingleChannel uint64

	cmd *cobra.Command
}

func newDropChannelGraphCommand() *cobra.Command {
	cc := &dropChannelGraphCommand{}
	cc.cmd = &cobra.Command{
		Use:   "dropchannelgraph",
		Short: "Remove all graph related data from a channel DB",
		Long: `This command removes all graph data from a channel DB,
forcing the lnd node to do a full graph sync.

Or if a single channel is specified, that channel is purged from the graph
without removing any other data.

CAUTION: Running this command will make it impossible to use the channel DB
with an older version of lnd. Downgrading is not possible and you'll need to
run lnd ` + lndVersion + ` or later after using this command!'`,
		Example: `chantools dropchannelgraph \
	--channeldb ~/.lnd/data/graph/mainnet/channel.db \
	--node_identity_key 03......

chantools dropchannelgraph \
	--channeldb ~/.lnd/data/graph/mainnet/channel.db \
	--single_channel 726607861215512345
	--node_identity_key 03......`,
		RunE: cc.Execute,
	}
	cc.cmd.Flags().StringVar(
		&cc.ChannelDB, "channeldb", "", "lnd channel.db file to drop "+
			"channels from",
	)
	cc.cmd.Flags().Uint64Var(
		&cc.SingleChannel, "single_channel", 0, "the single channel "+
			"identified by its short channel ID (CID) to remove "+
			"from the graph",
	)
	cc.cmd.Flags().StringVar(
		&cc.NodeIdentityKey, "node_identity_key", "", "your node's "+
			"identity public key",
	)
	cc.cmd.Flags().BoolVar(
		&cc.FixOnly, "fix_only", false, "fix an already empty graph "+
			"by re-adding the own node's channels",
	)

	return cc.cmd
}

func (c *dropChannelGraphCommand) Execute(_ *cobra.Command, _ []string) error {
	// Check that we have a channel DB.
	if c.ChannelDB == "" {
		return errors.New("channel DB is required")
	}
	db, err := lnd.OpenDB(c.ChannelDB, false)
	if err != nil {
		return fmt.Errorf("error opening rescue DB: %w", err)
	}
	defer func() { _ = db.Close() }()

	if c.NodeIdentityKey == "" {
		return errors.New("node identity key is required")
	}

	idKeyBytes, err := hex.DecodeString(c.NodeIdentityKey)
	if err != nil {
		return fmt.Errorf("error hex decoding node identity key: %w",
			err)
	}
	idKey, err := btcec.ParsePubKey(idKeyBytes)
	if err != nil {
		return fmt.Errorf("error parsing node identity key: %w", err)
	}

	if c.SingleChannel != 0 {
		log.Infof("Removing single channel %d", c.SingleChannel)
		return db.ChannelGraph().DeleteChannelEdges(
			true, false, c.SingleChannel,
		)
	}

	// Drop all channels, then insert our own channels into the graph again.
	if !c.FixOnly {
		log.Infof("Dropping all graph related buckets")

		rwTx, err := db.BeginReadWriteTx()
		if err != nil {
			return err
		}
		if err := rwTx.DeleteTopLevelBucket(nodeBucket); err != nil {
			return err
		}
		if err := rwTx.DeleteTopLevelBucket(edgeBucket); err != nil {
			return err
		}
		if err := rwTx.DeleteTopLevelBucket(graphMetaBucket); err != nil {
			return err
		}

		if err := rwTx.Commit(); err != nil {
			return err
		}
	}

	return insertOwnNodeAndChannels(idKey, db)
}

func insertOwnNodeAndChannels(idKey *btcec.PublicKey, db *channeldb.DB) error {
	openChannels, err := db.ChannelStateDB().FetchAllOpenChannels()
	if err != nil {
		return fmt.Errorf("error fetching open channels: %w", err)
	}

	graph := db.ChannelGraph()
	for _, openChan := range openChannels {
		edge, update, err := newChanAnnouncement(
			idKey, openChan.IdentityPub,
			&openChan.LocalChanCfg.MultiSigKey,
			openChan.RemoteChanCfg.MultiSigKey.PubKey,
			openChan.ShortChannelID, openChan.LocalChanCfg.MinHTLC,
			openChan.LocalChanCfg.MaxPendingAmount,
			openChan.Capacity, openChan.FundingOutpoint,
		)
		if err != nil {
			return fmt.Errorf("error creating announcement: %w",
				err)
		}

		if err := graph.AddChannelEdge(edge); err != nil {
			log.Warnf("Not adding channel edge %v because of "+
				"error: %v", edge.ChannelPoint, err)
		}
		if err := graph.UpdateEdgePolicy(update); err != nil {
			log.Warnf("Not updating edge policy %v because of "+
				"error: %v", update.ChannelID, err)
		}
	}

	return nil
}

func newChanAnnouncement(localPubKey, remotePubKey *btcec.PublicKey,
	localFundingKey *keychain.KeyDescriptor,
	remoteFundingKey *btcec.PublicKey, shortChanID lnwire.ShortChannelID,
	fwdMinHTLC, fwdMaxHTLC lnwire.MilliSatoshi, capacity btcutil.Amount,
	channelPoint wire.OutPoint) (*models.ChannelEdgeInfo,
	*models.ChannelEdgePolicy, error) {

	chainHash := *chainParams.GenesisHash

	// The unconditional section of the announcement is the ShortChannelID
	// itself which compactly encodes the location of the funding output
	// within the blockchain.
	chanAnn := &lnwire.ChannelAnnouncement1{
		ShortChannelID: shortChanID,
		Features:       lnwire.NewRawFeatureVector(),
		ChainHash:      chainHash,
	}

	// The chanFlags field indicates which directed edge of the channel is
	// being updated within the ChannelUpdateAnnouncement announcement
	// below. A value of zero means it's the edge of the "first" node and 1
	// being the other node.
	var chanFlags lnwire.ChanUpdateChanFlags

	// The lexicographical ordering of the two identity public keys of the
	// nodes indicates which of the nodes is "first". If our serialized
	// identity key is lower than theirs then we're the "first" node and
	// second otherwise.
	selfBytes := localPubKey.SerializeCompressed()
	remoteBytes := remotePubKey.SerializeCompressed()
	if bytes.Compare(selfBytes, remoteBytes) == -1 {
		copy(chanAnn.NodeID1[:], localPubKey.SerializeCompressed())
		copy(chanAnn.NodeID2[:], remotePubKey.SerializeCompressed())
		copy(chanAnn.BitcoinKey1[:], localFundingKey.PubKey.SerializeCompressed())
		copy(chanAnn.BitcoinKey2[:], remoteFundingKey.SerializeCompressed())

		// If we're the first node then update the chanFlags to
		// indicate the "direction" of the update.
		chanFlags = 0
	} else {
		copy(chanAnn.NodeID1[:], remotePubKey.SerializeCompressed())
		copy(chanAnn.NodeID2[:], localPubKey.SerializeCompressed())
		copy(chanAnn.BitcoinKey1[:], remoteFundingKey.SerializeCompressed())
		copy(chanAnn.BitcoinKey2[:], localFundingKey.PubKey.SerializeCompressed())

		// If we're the second node then update the chanFlags to
		// indicate the "direction" of the update.
		chanFlags = 1
	}

	var featureBuf bytes.Buffer
	if err := chanAnn.Features.Encode(&featureBuf); err != nil {
		log.Errorf("unable to encode features: %w", err)
		return nil, nil, err
	}

	edge := &models.ChannelEdgeInfo{
		ChannelID:        chanAnn.ShortChannelID.ToUint64(),
		ChainHash:        chanAnn.ChainHash,
		NodeKey1Bytes:    chanAnn.NodeID1,
		NodeKey2Bytes:    chanAnn.NodeID2,
		BitcoinKey1Bytes: chanAnn.BitcoinKey1,
		BitcoinKey2Bytes: chanAnn.BitcoinKey2,
		AuthProof:        nil,
		Features:         featureBuf.Bytes(),
		ExtraOpaqueData:  chanAnn.ExtraOpaqueData,
		Capacity:         capacity,
		ChannelPoint:     channelPoint,
	}

	// Our channel update message flags will signal that we support the
	// max_htlc field.
	msgFlags := lnwire.ChanUpdateRequiredMaxHtlc

	// We announce the channel with the default values. Some of
	// these values can later be changed by crafting a new ChannelUpdate.
	chanUpdateAnn := &lnwire.ChannelUpdate1{
		ShortChannelID: shortChanID,
		ChainHash:      chainHash,
		Timestamp:      uint32(time.Now().Unix()),
		MessageFlags:   msgFlags,
		ChannelFlags:   chanFlags,
		TimeLockDelta:  uint16(chainreg.DefaultBitcoinTimeLockDelta),

		// We use the HtlcMinimumMsat that the remote party required us
		// to use, as our ChannelUpdate will be used to carry HTLCs
		// towards them.
		HtlcMinimumMsat: fwdMinHTLC,
		HtlcMaximumMsat: fwdMaxHTLC,

		BaseFee: uint32(chainreg.DefaultBitcoinBaseFeeMSat),
		FeeRate: uint32(chainreg.DefaultBitcoinFeeRate),
	}

	update := &models.ChannelEdgePolicy{
		SigBytes:      chanUpdateAnn.Signature.ToSignatureBytes(),
		ChannelID:     chanAnn.ShortChannelID.ToUint64(),
		LastUpdate:    time.Now(),
		MessageFlags:  chanUpdateAnn.MessageFlags,
		ChannelFlags:  chanUpdateAnn.ChannelFlags,
		TimeLockDelta: chanUpdateAnn.TimeLockDelta,
		MinHTLC:       chanUpdateAnn.HtlcMinimumMsat,
		MaxHTLC:       chanUpdateAnn.HtlcMaximumMsat,
		FeeBaseMSat: lnwire.MilliSatoshi(
			chanUpdateAnn.BaseFee,
		),
		FeeProportionalMillionths: lnwire.MilliSatoshi(
			chanUpdateAnn.FeeRate,
		),
		ExtraOpaqueData: chanUpdateAnn.ExtraOpaqueData,
	}

	return edge, update, nil
}
