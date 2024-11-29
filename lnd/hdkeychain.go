package lnd

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/btcutil/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/lightningnetwork/lnd/fn"
	"github.com/lightningnetwork/lnd/input"
	"github.com/lightningnetwork/lnd/keychain"
	"github.com/lightningnetwork/lnd/shachain"
)

const (
	HardenedKeyStart            = uint32(hdkeychain.HardenedKeyStart)
	WalletDefaultDerivationPath = "m/84'/0'/0'"
	WalletBIP49DerivationPath   = "m/49'/0'/0'"
	WalletBIP86DerivationPath   = "m/86'/0'/0'"
	LndDerivationPath           = "m/1017'/%d'/%d'"

	AddressDeriveFromWallet = "fromseed"
)

type AddrType int

const (
	AddrTypeP2WKH AddrType = iota
	AddrTypeP2WSH
	AddrTypeP2TR
)

func DeriveChildren(key *hdkeychain.ExtendedKey, path []uint32) (
	*hdkeychain.ExtendedKey, error) {

	var currentKey = key
	for idx, pathPart := range path {
		derivedKey, err := currentKey.DeriveNonStandard(pathPart)
		if err != nil {
			return nil, err
		}

		// There's this special case in lnd's wallet (btcwallet) where
		// the coin type and account keys are always serialized as a
		// string and encrypted, which actually fixes the key padding
		// issue that makes the difference between DeriveNonStandard and
		// Derive. To replicate lnd's behavior exactly, we need to
		// serialize and de-serialize the extended key at the coin type
		// and account level (depth = 2 or depth = 3). This does not
		// apply to the default account (id = 0) because that is always
		// derived directly.
		depth := derivedKey.Depth()
		keyID := pathPart - hdkeychain.HardenedKeyStart
		nextID := uint32(0)
		if depth == 2 && len(path) > 2 {
			nextID = path[idx+1] - hdkeychain.HardenedKeyStart
		}
		if (depth == 2 && nextID != 0) || (depth == 3 && keyID != 0) {
			currentKey, err = hdkeychain.NewKeyFromString(
				derivedKey.String(),
			)
			if err != nil {
				return nil, err
			}
		} else {
			currentKey = derivedKey
		}
	}
	return currentKey, nil
}

func ParsePath(path string) ([]uint32, error) {
	path = strings.TrimSpace(path)
	if len(path) == 0 {
		return nil, errors.New("path cannot be empty")
	}
	if !strings.HasPrefix(path, "m/") {
		return nil, errors.New("path must start with m/")
	}
	parts := strings.Split(path, "/")
	indices := make([]uint32, len(parts)-1)
	for i := 1; i < len(parts); i++ {
		index := uint32(0)
		part := parts[i]
		if strings.Contains(parts[i], "'") {
			index += HardenedKeyStart
			part = strings.TrimRight(parts[i], "'")
		}
		parsed, err := strconv.Atoi(part)
		if err != nil {
			return nil, fmt.Errorf("could not parse part \"%s\": "+
				"%v", part, err)
		}
		indices[i-1] = index + uint32(parsed)
	}
	return indices, nil
}

func HardenedKey(key uint32) uint32 {
	return key + HardenedKeyStart
}

// DeriveKey derives the public key and private key in the WIF format for a
// given key path of the extended key.
func DeriveKey(extendedKey *hdkeychain.ExtendedKey, path string,
	params *chaincfg.Params) (*hdkeychain.ExtendedKey, *btcec.PublicKey,
	*btcutil.WIF, error) {

	parsedPath, err := ParsePath(path)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("could not parse derivation "+
			"path: %w", err)
	}
	derivedKey, err := DeriveChildren(extendedKey, parsedPath)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("could not derive children: "+
			"%w", err)
	}
	pubKey, err := derivedKey.ECPubKey()
	if err != nil {
		return nil, nil, nil, fmt.Errorf("could not derive public "+
			"key: %w", err)
	}

	privKey, err := derivedKey.ECPrivKey()
	if err != nil {
		return nil, nil, nil, fmt.Errorf("could not derive private "+
			"key: %w", err)
	}
	wif, err := btcutil.NewWIF(privKey, params, true)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("could not encode WIF: %w",
			err)
	}

	return derivedKey, pubKey, wif, nil
}

func PrivKeyFromPath(extendedKey *hdkeychain.ExtendedKey,
	path []uint32) (*btcec.PrivateKey, error) {

	derivedKey, err := DeriveChildren(extendedKey, path)
	if err != nil {
		return nil, fmt.Errorf("could not derive children: %w", err)
	}
	privKey, err := derivedKey.ECPrivKey()
	if err != nil {
		return nil, fmt.Errorf("could not derive private key: %w", err)
	}
	return privKey, nil
}

func ShaChainFromPath(extendedKey *hdkeychain.ExtendedKey, path []uint32,
	multiSigPubKey *btcec.PublicKey) (*shachain.RevocationProducer, error) {

	privKey, err := PrivKeyFromPath(extendedKey, path)
	if err != nil {
		return nil, err
	}

	// This is the legacy way where we just used the private key as the
	// revocation root directly.
	if multiSigPubKey == nil {
		revRoot, err := chainhash.NewHash(privKey.Serialize())
		if err != nil {
			return nil, fmt.Errorf("could not create revocation "+
				"root hash: %w", err)
		}
		return shachain.NewRevocationProducer(*revRoot), nil
	}

	// Perform an ECDH operation between the private key described in
	// nextRevocationKeyDesc and our public multisig key. The result will be
	// used to seed the revocation producer.
	revRoot, err := ECDH(privKey, multiSigPubKey)
	if err != nil {
		return nil, err
	}

	// Once we have the root, we can then generate our shachain producer
	// and from that generate the per-commitment point.
	return shachain.NewRevocationProducer(revRoot), nil
}

func IdentityPath(params *chaincfg.Params) string {
	return fmt.Sprintf(
		LndDerivationPath+"/0/0", params.HDCoinType,
		keychain.KeyFamilyNodeKey,
	)
}

func MultisigPath(params *chaincfg.Params, index int) string {
	return fmt.Sprintf(
		LndDerivationPath+"/0/%d", params.HDCoinType,
		keychain.KeyFamilyMultiSig, index,
	)
}

func AllDerivationPaths(params *chaincfg.Params) ([]string, [][]uint32, error) {
	mkPath := func(f keychain.KeyFamily) string {
		return fmt.Sprintf(
			LndDerivationPath, params.HDCoinType, uint32(f),
		)
	}
	pathStrings := []string{
		WalletBIP49DerivationPath,
		WalletDefaultDerivationPath,
		WalletBIP86DerivationPath,
		mkPath(keychain.KeyFamilyPaymentBase),
	}
	paths := make([][]uint32, len(pathStrings))
	for idx, path := range pathStrings {
		p, err := ParsePath(path)
		if err != nil {
			return nil, nil, err
		}
		paths[idx] = p
	}
	return pathStrings, paths, nil
}

// DecodeAddressHash returns the public key or script hash encoded in a native
// bech32 encoded SegWit address and whether it's a script hash or not.
func DecodeAddressHash(addr string, chainParams *chaincfg.Params) ([]byte, bool,
	error) {

	targetAddr, err := ParseAddress(addr, chainParams)
	if err != nil {
		return nil, false, err
	}

	// Must be a bech32 native SegWit address.
	var (
		isScriptHash = false
		targetHash   []byte
	)
	switch targetAddr.(type) {
	case *btcutil.AddressWitnessPubKeyHash:
		targetHash = targetAddr.ScriptAddress()

	case *btcutil.AddressWitnessScriptHash:
		isScriptHash = true
		targetHash = targetAddr.ScriptAddress()

	default:
		return nil, false, errors.New("address: must be a bech32 " +
			"P2WPKH or P2WSH address")
	}
	return targetHash, isScriptHash, nil
}

// ParseAddress attempts to parse the given address string into a native address
// for the given network.
func ParseAddress(addr string, chainParams *chaincfg.Params) (btcutil.Address,
	error) {

	// First parse address to get targetHash from it later.
	targetAddr, err := btcutil.DecodeAddress(addr, chainParams)
	if err != nil {
		return nil, fmt.Errorf("unable to decode address %s: %w", addr,
			err)
	}

	// Make the check on the decoded address according to the active
	// network (testnet or mainnet only).
	if !targetAddr.IsForNet(chainParams) {
		return nil, fmt.Errorf("address: %v is not valid for this "+
			"network: %v", targetAddr.String(), chainParams.Name,
		)
	}

	return targetAddr, nil
}

func GetWitnessAddrScript(addr btcutil.Address,
	chainParams *chaincfg.Params) ([]byte, error) {

	if !addr.IsForNet(chainParams) {
		return nil, fmt.Errorf("address %v is not for net %v", addr,
			chainParams.Name)
	}

	return txscript.PayToAddrScript(addr)
}

// GetP2WPKHScript creates a P2WKH output script from an address. If the address
// is not a P2WKH address, an error is returned.
func GetP2WPKHScript(addr string, chainParams *chaincfg.Params) ([]byte,
	error) {

	targetPubKeyHash, isScriptHash, err := DecodeAddressHash(
		addr, chainParams,
	)
	if err != nil {
		return nil, err
	}

	if isScriptHash {
		return nil, fmt.Errorf("address %s is not a P2WKH address",
			addr)
	}

	builder := txscript.NewScriptBuilder()
	builder.AddOp(txscript.OP_0)
	builder.AddData(targetPubKeyHash)

	return builder.Script()
}

// GetP2WSHScript creates a P2WSH output script from an address. If the address
// is not a P2WSH address, an error is returned.
func GetP2WSHScript(addr string, chainParams *chaincfg.Params) ([]byte,
	error) {

	targetScriptHash, isScriptHash, err := DecodeAddressHash(
		addr, chainParams,
	)
	if err != nil {
		return nil, err
	}

	if !isScriptHash {
		return nil, fmt.Errorf("address %s is not a P2WSH address",
			addr)
	}

	builder := txscript.NewScriptBuilder()
	builder.AddOp(txscript.OP_0)
	builder.AddData(targetScriptHash)

	return builder.Script()
}

func P2PKHAddr(pubKey *btcec.PublicKey,
	params *chaincfg.Params) (*btcutil.AddressPubKeyHash, error) {

	hash160 := btcutil.Hash160(pubKey.SerializeCompressed())
	addrP2PKH, err := btcutil.NewAddressPubKeyHash(hash160, params)
	if err != nil {
		return nil, fmt.Errorf("could not create address: %w", err)
	}

	return addrP2PKH, nil
}

func P2WKHAddr(pubKey *btcec.PublicKey,
	params *chaincfg.Params) (*btcutil.AddressWitnessPubKeyHash, error) {

	hash160 := btcutil.Hash160(pubKey.SerializeCompressed())
	return btcutil.NewAddressWitnessPubKeyHash(hash160, params)
}

func NP2WKHAddr(pubKey *btcec.PublicKey,
	params *chaincfg.Params) (*btcutil.AddressScriptHash, error) {

	hash160 := btcutil.Hash160(pubKey.SerializeCompressed())
	addrP2WKH, err := btcutil.NewAddressWitnessPubKeyHash(hash160, params)
	if err != nil {
		return nil, fmt.Errorf("could not create address: %w", err)
	}
	script, err := txscript.PayToAddrScript(addrP2WKH)
	if err != nil {
		return nil, fmt.Errorf("could not create script: %w", err)
	}
	return btcutil.NewAddressScriptHash(script, params)
}

func P2TRAddr(pubKey *btcec.PublicKey,
	params *chaincfg.Params) (*btcutil.AddressTaproot, error) {

	taprootKey := txscript.ComputeTaprootKeyNoScript(pubKey)
	return btcutil.NewAddressTaproot(
		schnorr.SerializePubKey(taprootKey), params,
	)
}

func P2AnchorStaticRemote(pubKey *btcec.PublicKey,
	params *chaincfg.Params) (*btcutil.AddressWitnessScriptHash, []byte,
	error) {

	commitScript, err := input.CommitScriptToRemoteConfirmed(pubKey)
	if err != nil {
		return nil, nil, fmt.Errorf("could not create script: %w", err)
	}
	scriptHash := sha256.Sum256(commitScript)
	p2wsh, err := btcutil.NewAddressWitnessScriptHash(scriptHash[:], params)
	return p2wsh, commitScript, err
}

func P2TaprootStaticRemote(pubKey *btcec.PublicKey,
	params *chaincfg.Params) (*btcutil.AddressTaproot,
	*input.CommitScriptTree, error) {

	// FIXME: fill tapLeaf for Tapscript root channels.
	var tapLeaf fn.Option[txscript.TapLeaf]

	scriptTree, err := input.NewRemoteCommitScriptTree(pubKey, tapLeaf)
	if err != nil {
		return nil, nil, fmt.Errorf("could not create script: %w", err)
	}

	addr, err := btcutil.NewAddressTaproot(
		schnorr.SerializePubKey(scriptTree.TaprootKey), params,
	)
	return addr, scriptTree, err
}

func CheckAddress(addr string, chainParams *chaincfg.Params, allowDerive bool,
	hint string, allowedTypes ...AddrType) error {

	// We generally always want an address to be specified. If one should
	// be derived from the wallet automatically, the user should specify
	// "derive" as the address.
	if addr == "" {
		return fmt.Errorf("%s address cannot be empty", hint)
	}

	// If we're allowed to derive an address from the wallet, we can skip
	// the rest of the checks.
	if allowDerive && addr == AddressDeriveFromWallet {
		return nil
	}

	parsedAddr, err := ParseAddress(addr, chainParams)
	if err != nil {
		return fmt.Errorf("%s address is invalid: %w", hint, err)
	}

	if !matchAddrType(parsedAddr, allowedTypes...) {
		return fmt.Errorf("%s address is of wrong type, allowed "+
			"types: %s", hint, addrTypesToString(allowedTypes))
	}

	return nil
}

func PrepareWalletAddress(addr string, chainParams *chaincfg.Params,
	estimator *input.TxWeightEstimator, rootKey *hdkeychain.ExtendedKey,
	hint string) ([]byte, error) {

	// We already checked if deriving a new address is allowed in a previous
	// step, so we can just go ahead and do it now if requested.
	if addr == AddressDeriveFromWallet {
		// To maximize compatibility and recoverability, we always
		// derive the very first P2WKH address from the wallet.
		// This corresponds to the derivation path: m/84'/0'/0'/0/0.
		derivedKey, err := DeriveChildren(rootKey, []uint32{
			HardenedKeyStart + waddrmgr.KeyScopeBIP0084.Purpose,
			HardenedKeyStart + chainParams.HDCoinType,
			HardenedKeyStart + 0, 0, 0,
		})
		if err != nil {
			return nil, err
		}

		derivedPubKey, err := derivedKey.ECPubKey()
		if err != nil {
			return nil, err
		}

		p2wkhAddr, err := P2WKHAddr(derivedPubKey, chainParams)
		if err != nil {
			return nil, err
		}

		return txscript.PayToAddrScript(p2wkhAddr)
	}

	parsedAddr, err := ParseAddress(addr, chainParams)
	if err != nil {
		return nil, fmt.Errorf("%s address is invalid: %w", hint, err)
	}

	// Exit early if we don't need to estimate the weight.
	if estimator == nil {
		return txscript.PayToAddrScript(parsedAddr)
	}

	// These are the three address types that we support in general. We
	// should have checked that we get the correct type in a previous step.
	switch parsedAddr.(type) {
	case *btcutil.AddressWitnessPubKeyHash:
		estimator.AddP2WKHOutput()

	case *btcutil.AddressWitnessScriptHash:
		estimator.AddP2WSHOutput()

	case *btcutil.AddressTaproot:
		estimator.AddP2TROutput()

	default:
		return nil, fmt.Errorf("%s address is of wrong type", hint)
	}

	return txscript.PayToAddrScript(parsedAddr)
}

func matchAddrType(addr btcutil.Address, allowedTypes ...AddrType) bool {
	contains := func(allowedTypes []AddrType, addrType AddrType) bool {
		for _, allowedType := range allowedTypes {
			if allowedType == addrType {
				return true
			}
		}

		return false
	}

	switch addr.(type) {
	case *btcutil.AddressWitnessPubKeyHash:
		return contains(allowedTypes, AddrTypeP2WKH)

	case *btcutil.AddressWitnessScriptHash:
		return contains(allowedTypes, AddrTypeP2WSH)

	case *btcutil.AddressTaproot:
		return contains(allowedTypes, AddrTypeP2TR)

	default:
		return false
	}
}

func addrTypesToString(allowedTypes []AddrType) string {
	var types []string
	for _, allowedType := range allowedTypes {
		switch allowedType {
		case AddrTypeP2WKH:
			types = append(types, "P2WKH")

		case AddrTypeP2WSH:
			types = append(types, "P2WSH")

		case AddrTypeP2TR:
			types = append(types, "P2TR")
		}
	}

	return strings.Join(types, ", ")
}

type HDKeyRing struct {
	ExtendedKey *hdkeychain.ExtendedKey
	ChainParams *chaincfg.Params
}

func (r *HDKeyRing) DeriveNextKey(_ keychain.KeyFamily) (
	keychain.KeyDescriptor, error) {

	return keychain.KeyDescriptor{}, nil
}

func (r *HDKeyRing) DeriveKey(keyLoc keychain.KeyLocator) (
	keychain.KeyDescriptor, error) {

	var empty = keychain.KeyDescriptor{}
	derivedKey, err := DeriveChildren(r.ExtendedKey, []uint32{
		HardenedKeyStart + uint32(keychain.BIP0043Purpose),
		HardenedKeyStart + r.ChainParams.HDCoinType,
		HardenedKeyStart + uint32(keyLoc.Family),
		0,
		keyLoc.Index,
	})
	if err != nil {
		return empty, err
	}

	derivedPubKey, err := derivedKey.ECPubKey()
	if err != nil {
		return empty, err
	}
	return keychain.KeyDescriptor{
		KeyLocator: keychain.KeyLocator{
			Family: keyLoc.Family,
			Index:  keyLoc.Index,
		},
		PubKey: derivedPubKey,
	}, nil
}

// CheckDescriptor checks if a key descriptor is correct by making sure that we
// can derive the key that it describes.
func (r *HDKeyRing) CheckDescriptor(
	keyDesc keychain.KeyDescriptor) error {

	// A check doesn't make sense if there is no public key set.
	if keyDesc.PubKey == nil {
		return errors.New("no public key provided to check")
	}

	// Performance fix, derive static path only once.
	familyKey, err := DeriveChildren(r.ExtendedKey, []uint32{
		HardenedKeyStart + uint32(keychain.BIP0043Purpose),
		HardenedKeyStart + r.ChainParams.HDCoinType,
		HardenedKeyStart + uint32(keyDesc.Family),
		0,
	})
	if err != nil {
		return err
	}

	// Scan the same key range as lnd would do on channel restore.
	for i := range keychain.MaxKeyRangeScan {
		child, err := DeriveChildren(familyKey, []uint32{uint32(i)})
		if err != nil {
			return err
		}
		pubKey, err := child.ECPubKey()
		if err != nil {
			return err
		}
		if !pubKey.IsEqual(keyDesc.PubKey) {
			continue
		}
		// If we found the key, we can abort and signal success.
		return nil
	}

	// We scanned the max range and didn't find a key. It's very likely not
	// derivable with the given information.
	return keychain.ErrCannotDerivePrivKey
}

// NodePubKey returns the public key that represents an lnd node's public
// network identity.
func (r *HDKeyRing) NodePubKey() (*btcec.PublicKey, error) {
	keyDesc, err := r.DeriveKey(keychain.KeyLocator{
		Family: keychain.KeyFamilyNodeKey,
		Index:  0,
	})
	if err != nil {
		return nil, err
	}

	return keyDesc.PubKey, nil
}
