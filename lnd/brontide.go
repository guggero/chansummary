package lnd

import (
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/ecdsa"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/connmgr"
	"github.com/lightningnetwork/lnd/aliasmgr"
	"github.com/lightningnetwork/lnd/brontide"
	"github.com/lightningnetwork/lnd/channeldb"
	"github.com/lightningnetwork/lnd/discovery"
	"github.com/lightningnetwork/lnd/feature"
	"github.com/lightningnetwork/lnd/htlcswitch"
	"github.com/lightningnetwork/lnd/htlcswitch/hodl"
	"github.com/lightningnetwork/lnd/keychain"
	"github.com/lightningnetwork/lnd/lncfg"
	"github.com/lightningnetwork/lnd/lnpeer"
	"github.com/lightningnetwork/lnd/lntest/mock"
	"github.com/lightningnetwork/lnd/lnwallet"
	"github.com/lightningnetwork/lnd/lnwallet/chainfee"
	"github.com/lightningnetwork/lnd/lnwire"
	"github.com/lightningnetwork/lnd/netann"
	"github.com/lightningnetwork/lnd/peer"
	"github.com/lightningnetwork/lnd/pool"
	"github.com/lightningnetwork/lnd/queue"
	"github.com/lightningnetwork/lnd/routing/route"
	"github.com/lightningnetwork/lnd/ticker"
)

const (
	defaultChannelCommitBatchSize = 10
	defaultCoopCloseTargetConfs   = 6
)

var (
	chanEnableTimeout            = 19 * time.Minute
	defaultChannelCommitInterval = 50 * time.Millisecond
	defaultPendingCommitInterval = 1 * time.Minute
)

func ConnectPeer(conn *brontide.Conn, connReq *connmgr.ConnReq,
	netParams *chaincfg.Params,
	identityECDH keychain.SingleKeyECDH) (*peer.Brontide, error) {

	featureMgr, err := feature.NewManager(feature.Config{})
	if err != nil {
		return nil, err
	}

	initFeatures := featureMgr.Get(feature.SetInit)
	legacyFeatures := featureMgr.Get(feature.SetLegacyGlobal)

	addr := conn.RemoteAddr()
	pubKey := conn.RemotePub()
	peerAddr := &lnwire.NetAddress{
		IdentityKey: pubKey,
		Address:     addr,
		ChainNet:    netParams.Net,
	}
	errBuffer, err := queue.NewCircularBuffer(500)
	if err != nil {
		return nil, err
	}

	pongBuf := make([]byte, lnwire.MaxPongBytes)

	writeBufferPool := pool.NewWriteBuffer(
		pool.DefaultWriteBufferGCInterval,
		pool.DefaultWriteBufferExpiryInterval,
	)
	writePool := pool.NewWrite(
		writeBufferPool, lncfg.DefaultWriteWorkers,
		pool.DefaultWorkerTimeout,
	)

	readBufferPool := pool.NewReadBuffer(
		pool.DefaultReadBufferGCInterval,
		pool.DefaultReadBufferExpiryInterval,
	)
	readPool := pool.NewRead(
		readBufferPool, lncfg.DefaultWriteWorkers,
		pool.DefaultWorkerTimeout,
	)
	commitFee := chainfee.SatPerKVByte(
		lnwallet.DefaultAnchorsCommitMaxFeeRateSatPerVByte * 1000,
	)

	if err := writePool.Start(); err != nil {
		return nil, fmt.Errorf("unable to start write pool: %w", err)
	}
	if err := readPool.Start(); err != nil {
		return nil, fmt.Errorf("unable to start read pool: %w", err)
	}

	channelDB, err := channeldb.Open(os.TempDir())
	if err != nil {
		return nil, err
	}

	gossiper := discovery.New(discovery.Config{
		ChainHash: *netParams.GenesisHash,
		Broadcast: func(_ map[route.Vertex]struct{},
			_ ...lnwire.Message) error {

			return nil
		},
		NotifyWhenOnline: func([33]byte, chan<- lnpeer.Peer) {
		},
		NotifyWhenOffline: func(_ [33]byte) <-chan struct{} {
			return make(chan struct{})
		},
		FetchSelfAnnouncement: func() lnwire.NodeAnnouncement {
			return lnwire.NodeAnnouncement{}
		},
		ProofMatureDelta:    0,
		TrickleDelay:        time.Millisecond * 50,
		RetransmitTicker:    ticker.New(time.Minute * 30),
		RebroadcastInterval: time.Hour * 24,
		RotateTicker: ticker.New(
			discovery.DefaultSyncerRotationInterval,
		),
		HistoricalSyncTicker: ticker.New(
			discovery.DefaultHistoricalSyncInterval,
		),
		NumActiveSyncers:        0,
		MinimumBatchSize:        10,
		SubBatchDelay:           discovery.DefaultSubBatchDelay,
		IgnoreHistoricalFilters: true,
		PinnedSyncers:           make(map[route.Vertex]struct{}),
		MaxChannelUpdateBurst:   discovery.DefaultMaxChannelUpdateBurst,
		ChannelUpdateInterval:   discovery.DefaultChannelUpdateInterval,
		IsAlias:                 aliasmgr.IsAlias,
		SignAliasUpdate: func(
			*lnwire.ChannelUpdate1) (*ecdsa.Signature, error) {

			return nil, errors.New("unimplemented")
		},
		FindBaseByAlias: func(
			lnwire.ShortChannelID) (lnwire.ShortChannelID, error) {

			return lnwire.ShortChannelID{},
				errors.New("unimplemented")
		},
		GetAlias: func(_ lnwire.ChannelID) (lnwire.ShortChannelID,
			error) {

			return lnwire.ShortChannelID{},
				errors.New("unimplemented")
		},
		FindChannel: func(*btcec.PublicKey,
			lnwire.ChannelID) (*channeldb.OpenChannel, error) {

			return nil, errors.New("unimplemented")
		},
	}, &keychain.KeyDescriptor{
		KeyLocator: keychain.KeyLocator{},
		PubKey:     identityECDH.PubKey(),
	})

	pCfg := peer.Config{
		Conn:                    conn,
		ConnReq:                 connReq,
		Addr:                    peerAddr,
		Inbound:                 false,
		Features:                initFeatures,
		LegacyFeatures:          legacyFeatures,
		OutgoingCltvRejectDelta: lncfg.DefaultOutgoingCltvRejectDelta,
		ChanActiveTimeout:       chanEnableTimeout,
		ErrorBuffer:             errBuffer,
		WritePool:               writePool,
		ReadPool:                readPool,
		ChannelDB:               channelDB.ChannelStateDB(),
		AuthGossiper:            gossiper,
		ChainNotifier:           &mock.ChainNotifier{},
		DisconnectPeer: func(key *btcec.PublicKey) error {
			fmt.Printf("Peer %x disconnected\n",
				key.SerializeCompressed())
			return nil
		},
		GenNodeAnnouncement: func(_ ...netann.NodeAnnModifier) (
			lnwire.NodeAnnouncement, error) {

			return lnwire.NodeAnnouncement{},
				errors.New("unimplemented")
		},

		PongBuf: pongBuf,

		PrunePersistentPeerConnection: func(_ [33]byte) {},

		FetchLastChanUpdate: func(_ lnwire.ShortChannelID) (
			*lnwire.ChannelUpdate1, error) {

			return nil, errors.New("unimplemented")
		},

		Hodl:                    &hodl.Config{},
		UnsafeReplay:            false,
		MaxOutgoingCltvExpiry:   htlcswitch.DefaultMaxOutgoingCltvExpiry,
		MaxChannelFeeAllocation: htlcswitch.DefaultMaxLinkFeeAllocation,
		CoopCloseTargetConfs:    defaultCoopCloseTargetConfs,
		MaxAnchorsCommitFeeRate: commitFee.FeePerKWeight(),
		ChannelCommitInterval:   defaultChannelCommitInterval,
		PendingCommitInterval:   defaultPendingCommitInterval,
		ChannelCommitBatchSize:  defaultChannelCommitBatchSize,
		HandleCustomMessage: func(peer [33]byte,
			msg *lnwire.Custom) error {

			fmt.Printf("Received custom message from %x: %v\n",
				peer[:], msg)
			return nil
		},
		GetAliases: func(
			_ lnwire.ShortChannelID) []lnwire.ShortChannelID {

			return nil
		},
		RequestAlias: func() (lnwire.ShortChannelID, error) {
			return lnwire.ShortChannelID{}, nil
		},
		AddLocalAlias: func(_, _ lnwire.ShortChannelID,
			_, _ bool) error {

			return nil
		},
		Quit: make(chan struct{}),
	}

	copy(pCfg.PubKeyBytes[:], peerAddr.IdentityKey.SerializeCompressed())
	copy(pCfg.ServerPubKey[:], identityECDH.PubKey().SerializeCompressed())

	p := peer.NewBrontide(pCfg)
	if err := p.Start(); err != nil {
		return nil, err
	}

	return p, nil
}
