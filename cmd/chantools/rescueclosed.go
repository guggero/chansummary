package main

import (
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"regexp"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/btcutil/hdkeychain"
	"github.com/lightninglabs/chantools/dataformat"
	"github.com/lightninglabs/chantools/lnd"
	"github.com/lightningnetwork/lnd/channeldb"
	"github.com/lightningnetwork/lnd/input"
	"github.com/lightningnetwork/lnd/keychain"
	"github.com/spf13/cobra"
)

var (
	defaultNumKeys uint32 = 5000
	cache          []*cacheEntry

	errAddrNotFound = errors.New("addr not found")

	patternCommitPoint = regexp.MustCompile(`commit_point=([0-9a-f]{66})`)
)

type cacheEntry struct {
	privKey *btcec.PrivateKey
	keyDesc *keychain.KeyDescriptor
}

type rescueClosedCommand struct {
	ChannelDB   string
	Addr        string
	CommitPoint string
	LndLog      string
	NumKeys     uint32

	rootKey *rootKey
	inputs  *inputFlags
	cmd     *cobra.Command
}

func newRescueClosedCommand() *cobra.Command {
	cc := &rescueClosedCommand{}
	cc.cmd = &cobra.Command{
		Use: "rescueclosed",
		Short: "Try finding the private keys for funds that " +
			"are in outputs of remotely force-closed channels",
		Long: `If channels have already been force-closed by the remote
peer, this command tries to find the private keys to sweep the funds from the
output that belongs to our side. This can only be used if we have a channel DB
that contains the latest commit point. Normally you would use SCB to get the
funds from those channels. But this method can help if the other node doesn't
know about the channels any more but we still have the channel.db from the
moment they force-closed.

NOTE: Unless your channel was opened before 2019, you very likely don't need to
use this command as things were simplified. Use 'chantools sweepremoteclosed'
instead if the remote party has already closed the channel.

The alternative use case for this command is if you got the commit point by
running the fund-recovery branch of my guggero/lnd fork (see 
https://github.com/guggero/lnd/releases for a binary release) in combination
with the fakechanbackup command. Then you need to specify the --commit_point and 
--force_close_addr flags instead of the --channeldb and --fromsummary flags.

If you need to rescue a whole bunch of channels all at once, you can also
specify the --fromsummary and --lnd_log flags to automatically look for force
close addresses in the summary and the corresponding commit points in the
lnd log file. This only works if lnd is running the fund-recovery branch of my
guggero/lnd (https://github.com/guggero/lnd/releases) fork and only if the
debuglevel is set to debug (lnd.conf, set 'debuglevel=debug').`,
		Example: `chantools rescueclosed \
	--fromsummary results/summary-xxxxxx.json \
	--channeldb ~/.lnd/data/graph/mainnet/channel.db

chantools rescueclosed --force_close_addr bc1q... --commit_point 03xxxx

chantools rescueclosed --fromsummary results/summary-xxxxxx.json \
	--lnd_log ~/.lnd/logs/bitcoin/mainnet/lnd.log`,
		RunE: cc.Execute,
	}
	cc.cmd.Flags().StringVar(
		&cc.ChannelDB, "channeldb", "", "lnd channel.db file to use "+
			"for rescuing force-closed channels",
	)
	cc.cmd.Flags().StringVar(
		&cc.Addr, "force_close_addr", "", "the address the channel "+
			"was force closed to, look up in block explorer by "+
			"following funding txid",
	)
	cc.cmd.Flags().StringVar(
		&cc.CommitPoint, "commit_point", "", "the commit point that "+
			"was obtained from the logs after running the "+
			"fund-recovery branch of guggero/lnd",
	)
	cc.cmd.Flags().StringVar(
		&cc.LndLog, "lnd_log", "", "the lnd log file to read to get "+
			"the commit_point values when rescuing multiple "+
			"channels at the same time",
	)
	cc.cmd.Flags().Uint32Var(
		&cc.NumKeys, "num_keys", defaultNumKeys, "the number of keys "+
			"to derive for the brute force attack",
	)
	cc.rootKey = newRootKey(cc.cmd, "decrypting the backup")
	cc.inputs = newInputFlags(cc.cmd)

	return cc.cmd
}

func (c *rescueClosedCommand) Execute(_ *cobra.Command, _ []string) error {
	extendedKey, err := c.rootKey.read()
	if err != nil {
		return fmt.Errorf("error reading root key: %w", err)
	}

	// What way of recovery has the user chosen? From summary and DB or from
	// address and commit point?
	switch {
	case c.ChannelDB != "":
		db, err := lnd.OpenDB(c.ChannelDB, true)
		if err != nil {
			return fmt.Errorf("error opening rescue DB: %w", err)
		}

		// Parse channel entries from any of the possible input files.
		entries, err := c.inputs.parseInputType()
		if err != nil {
			return err
		}

		commitPoints, err := commitPointsFromDB(db.ChannelStateDB())
		if err != nil {
			return fmt.Errorf("error reading commit points from "+
				"db: %w", err)
		}
		return rescueClosedChannels(
			c.NumKeys, extendedKey, entries, commitPoints,
		)

	case c.Addr != "":
		// First parse address to get targetPubKeyHash from it later.
		targetAddr, err := btcutil.DecodeAddress(c.Addr, chainParams)
		if err != nil {
			return fmt.Errorf("error parsing addr: %w", err)
		}

		// Now parse the commit point.
		commitPointRaw, err := hex.DecodeString(c.CommitPoint)
		if err != nil {
			return fmt.Errorf("error decoding commit point: %w",
				err)
		}
		commitPoint, err := btcec.ParsePubKey(commitPointRaw)
		if err != nil {
			return fmt.Errorf("error parsing commit point: %w", err)
		}

		return rescueClosedChannel(
			c.NumKeys, extendedKey, targetAddr, commitPoint,
		)

	case c.LndLog != "":
		// Parse channel entries from any of the possible input files.
		entries, err := c.inputs.parseInputType()
		if err != nil {
			return err
		}

		commitPoints, err := commitPointsFromLogFile(c.LndLog)
		if err != nil {
			return fmt.Errorf("error parsing commit points from "+
				"log file: %w", err)
		}
		return rescueClosedChannels(
			c.NumKeys, extendedKey, entries, commitPoints,
		)

	default:
		return errors.New("you either need to specify --channeldb and " +
			"--fromsummary or --force_close_addr and " +
			"--commit_point but not a mixture of them")
	}
}

func commitPointsFromDB(chanDb *channeldb.ChannelStateDB) ([]*btcec.PublicKey,
	error) {

	var result []*btcec.PublicKey

	channels, err := chanDb.FetchAllChannels()
	if err != nil {
		return nil, err
	}

	// Try naive/lucky guess with information from channel DB.
	for _, channel := range channels {
		if channel.RemoteNextRevocation != nil {
			result = append(result, channel.RemoteNextRevocation)
		}

		if channel.RemoteCurrentRevocation != nil {
			result = append(result, channel.RemoteCurrentRevocation)
		}
	}

	return result, nil
}

func commitPointsFromLogFile(lndLog string) ([]*btcec.PublicKey, error) {
	logFileBytes, err := os.ReadFile(lndLog)
	if err != nil {
		return nil, fmt.Errorf("error reading log file %s: %w", lndLog,
			err)
	}

	allMatches := patternCommitPoint.FindAllStringSubmatch(
		string(logFileBytes), -1,
	)
	dedupMap := make(map[string]*btcec.PublicKey, len(allMatches))
	for _, groups := range allMatches {
		commitPointBytes, err := hex.DecodeString(groups[1])
		if err != nil {
			return nil, fmt.Errorf("error parsing commit point "+
				"hex: %w", err)
		}

		commitPoint, err := btcec.ParsePubKey(commitPointBytes)
		if err != nil {
			return nil, fmt.Errorf("error parsing commit point: %w",
				err)
		}

		dedupMap[groups[1]] = commitPoint
	}

	result := make([]*btcec.PublicKey, 0, len(dedupMap))
	for _, commitPoint := range dedupMap {
		result = append(result, commitPoint)
	}

	log.Infof("Extracted %d commit points from log file %s", len(result),
		lndLog)

	return result, nil
}

func rescueClosedChannels(numKeys uint32, extendedKey *hdkeychain.ExtendedKey,
	entries []*dataformat.SummaryEntry,
	possibleCommitPoints []*btcec.PublicKey) error {

	err := fillCache(numKeys, extendedKey)
	if err != nil {
		return err
	}

	// Add a nil commit point to the list of possible commit points to also
	// try brute forcing a static_remote_key address.
	possibleCommitPoints = append(possibleCommitPoints, nil)

	// We'll also keep track of all rescued keys for an additional log
	// output.
	resultMap := make(map[string]string)

	// Try naive/lucky guess by trying out all combinations.
outer:
	for _, entry := range entries {
		// Don't try anything with open channels, fully closed channels
		// or channels where we already have the private key.
		if entry.ClosingTX == nil ||
			entry.ClosingTX.AllOutsSpent ||
			(entry.ClosingTX.OurAddr == "" &&
				entry.ClosingTX.ToRemoteAddr == "") ||
			entry.ClosingTX.SweepPrivkey != "" {

			continue
		}

		// Try with every possible commit point now.
		for _, commitPoint := range possibleCommitPoints {
			addr := entry.ClosingTX.OurAddr
			if addr == "" {
				addr = entry.ClosingTX.ToRemoteAddr
			}

			wif, err := addrInCache(numKeys, addr, commitPoint)
			switch {
			case err == nil:
				entry.ClosingTX.SweepPrivkey = wif
				resultMap[addr] = wif

				continue outer

			case errors.Is(err, errAddrNotFound):

			default:
				return err
			}
		}
	}

	importStr := ""
	for addr, wif := range resultMap {
		importStr += fmt.Sprintf(`importprivkey "%s" "%s" false%s`, wif,
			addr, "\n")
	}
	log.Infof("Found %d private keys! Import them into bitcoind through "+
		"the console by pasting: \n%srescanblockchain 481824\n",
		len(resultMap), importStr)

	summaryBytes, err := json.MarshalIndent(&dataformat.SummaryEntryFile{
		Channels: entries,
	}, "", " ")
	if err != nil {
		return err
	}
	fileName := fmt.Sprintf("results/rescueclosed-%s.json",
		time.Now().Format("2006-01-02-15-04-05"))
	log.Infof("Writing result to %s", fileName)
	return os.WriteFile(fileName, summaryBytes, 0644)
}

func rescueClosedChannel(numKeys uint32, extendedKey *hdkeychain.ExtendedKey,
	addr btcutil.Address, commitPoint *btcec.PublicKey) error {

	// Make the check on the decoded address according to the active
	// network (testnet or mainnet only).
	if !addr.IsForNet(chainParams) {
		return fmt.Errorf("address: %v is not valid for this network: "+
			"%v", addr, chainParams.Name)
	}

	// Must be a bech32 native SegWit address.
	switch addr.(type) {
	case *btcutil.AddressWitnessPubKeyHash:
		log.Infof("Brute forcing private key for tweaked public key "+
			"hash %x\n", addr.ScriptAddress())

	default:
		return errors.New("address: must be a bech32 P2WPKH address")
	}

	err := fillCache(numKeys, extendedKey)
	if err != nil {
		return err
	}

	wif, err := addrInCache(numKeys, addr.String(), commitPoint)
	switch {
	case err == nil:
		log.Infof("Found private key %s for address %v!", wif, addr)

		return nil

	case errors.Is(err, errAddrNotFound):
		// Try again as a static_remote_key.

	default:
		return err
	}

	// Try again as a static_remote_key address.
	wif, err = addrInCache(numKeys, addr.String(), nil)
	switch {
	case err == nil:
		log.Infof("Found private key %s for address %v!", wif, addr)

		return nil

	case errors.Is(err, errAddrNotFound):
		return fmt.Errorf("did not find private key for address %v",
			addr)

	default:
		return err
	}
}

func addrInCache(numKeys uint32, addr string,
	perCommitPoint *btcec.PublicKey) (string, error) {

	targetPubKeyHash, scriptHash, err := lnd.DecodeAddressHash(
		addr, chainParams,
	)
	if err != nil {
		return "", fmt.Errorf("error parsing addr: %w", err)
	}
	if scriptHash {
		return "", errors.New("address must be a P2WPKH address")
	}

	// If the commit point is nil, we try with plain private keys to match
	// static_remote_key outputs.
	if perCommitPoint == nil {
		for i := range numKeys {
			cacheEntry := cache[i]
			hashedPubKey := btcutil.Hash160(
				cacheEntry.keyDesc.PubKey.SerializeCompressed(),
			)
			equal := subtle.ConstantTimeCompare(
				targetPubKeyHash, hashedPubKey,
			)
			if equal == 1 {
				wif, err := btcutil.NewWIF(
					cacheEntry.privKey, chainParams, true,
				)
				if err != nil {
					return "", err
				}
				log.Infof("The private key for addr %s "+
					"(static_remote_key) found after "+
					"%d tries: %s", addr, i, wif.String(),
				)
				return wif.String(), nil
			}
		}

		return "", errAddrNotFound
	}

	// Loop through all cached payment base point keys, tweak each of it
	// with the per_commit_point and see if the hashed public key
	// corresponds to the target pubKeyHash of the given address.
	for i := range numKeys {
		cacheEntry := cache[i]
		basePoint := cacheEntry.keyDesc.PubKey
		tweakedPubKey := input.TweakPubKey(basePoint, perCommitPoint)
		tweakBytes := input.SingleTweakBytes(perCommitPoint, basePoint)
		tweakedPrivKey := input.TweakPrivKey(
			cacheEntry.privKey, tweakBytes,
		)
		hashedPubKey := btcutil.Hash160(
			tweakedPubKey.SerializeCompressed(),
		)
		equal := subtle.ConstantTimeCompare(
			targetPubKeyHash, hashedPubKey,
		)
		if equal == 1 {
			wif, err := btcutil.NewWIF(
				tweakedPrivKey, chainParams, true,
			)
			if err != nil {
				return "", err
			}
			log.Infof("The private key for addr %s found after "+
				"%d tries: %s", addr, i, wif.String(),
			)
			return wif.String(), nil
		}
	}

	return "", errAddrNotFound
}

func keyInCache(numKeys uint32, addr string,
	perCommitPoint *btcec.PublicKey) (*keychain.KeyDescriptor, []byte,
	error) {

	targetPubKeyHash, scriptHash, err := lnd.DecodeAddressHash(
		addr, chainParams,
	)
	if err != nil {
		return nil, nil, fmt.Errorf("error parsing addr: %w", err)
	}
	if scriptHash {
		return nil, nil, errors.New("address must be a P2WPKH address")
	}

	for i := range numKeys {
		cacheEntry := cache[i]
		basePoint := cacheEntry.keyDesc.PubKey
		tweakedPubKey := input.TweakPubKey(basePoint, perCommitPoint)
		tweakBytes := input.SingleTweakBytes(perCommitPoint, basePoint)
		hashedPubKey := btcutil.Hash160(
			tweakedPubKey.SerializeCompressed(),
		)
		equal := subtle.ConstantTimeCompare(
			targetPubKeyHash, hashedPubKey,
		)
		if equal == 1 {
			return cacheEntry.keyDesc, tweakBytes, nil
		}
	}

	return nil, nil, errAddrNotFound
}

func fillCache(numKeys uint32, extendedKey *hdkeychain.ExtendedKey) error {
	cache = make([]*cacheEntry, numKeys)

	for i := range numKeys {
		key, err := lnd.DeriveChildren(extendedKey, []uint32{
			lnd.HardenedKeyStart + uint32(keychain.BIP0043Purpose),
			lnd.HardenedKeyStart + chainParams.HDCoinType,
			lnd.HardenedKeyStart + uint32(
				keychain.KeyFamilyPaymentBase,
			), 0, i,
		})
		if err != nil {
			return err
		}
		privKey, err := key.ECPrivKey()
		if err != nil {
			return err
		}
		pubKey, err := key.ECPubKey()
		if err != nil {
			return err
		}
		cache[i] = &cacheEntry{
			privKey: privKey,
			keyDesc: &keychain.KeyDescriptor{
				KeyLocator: keychain.KeyLocator{
					Family: keychain.KeyFamilyPaymentBase,
					Index:  i,
				},
				PubKey: pubKey,
			},
		}

		if i > 0 && i%10000 == 0 {
			fmt.Printf("Filled cache with %d of %d keys.\n",
				i, numKeys)
		}
	}
	return nil
}
