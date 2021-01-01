package main

import (
	"fmt"

	"github.com/btcsuite/btcutil"
	"github.com/btcsuite/btcutil/hdkeychain"
	"github.com/guggero/chantools/lnd"
	"github.com/spf13/cobra"
)

const deriveKeyFormat = `
Path:				%s
Network: 			%s
Public key: 			%x
Extended public key (xpub): 	%v
Address: 			%v
Legacy address: 		%v
Private key (WIF): 		%s
Extended private key (xprv):	%s
`

type deriveKeyCommand struct {
	Path   string
	Neuter bool

	rootKey *rootKey
	cmd     *cobra.Command
}

func newDeriveKeyCommand() *cobra.Command {
	cc := &deriveKeyCommand{}
	cc.cmd = &cobra.Command{
		Use:   "derivekey",
		Short: "Derive a key with a specific derivation path",
		Long: `This command derives a single key with the given BIP32
derivation path from the root key and prints it to the console.`,
		Example: `chantools derivekey --rootkey xprvxxxxxxxxxx \
	--path "m/1017'/0'/5'/0/0'" --neuter`,
		RunE: cc.Execute,
	}
	cc.cmd.Flags().StringVar(
		&cc.Path, "path", "", "BIP32 derivation path to derive; must "+
			"start with \"m/\"",
	)
	cc.cmd.Flags().BoolVar(
		&cc.Neuter, "neuter", false, "don't output private key(s), "+
			"only public key(s)",
	)

	cc.rootKey = newRootKey(cc.cmd, "decrypting the backup")

	return cc.cmd
}

func (c *deriveKeyCommand) Execute(_ *cobra.Command, _ []string) error {
	extendedKey, err := c.rootKey.read()
	if err != nil {
		return fmt.Errorf("error reading root key: %v", err)
	}

	return deriveKey(extendedKey, c.Path, c.Neuter)
}

func deriveKey(extendedKey *hdkeychain.ExtendedKey, path string,
	neuter bool) error {

	child, pubKey, wif, err := lnd.DeriveKey(extendedKey, path, chainParams)
	if err != nil {
		return fmt.Errorf("could not derive keys: %v", err)
	}
	neutered, err := child.Neuter()
	if err != nil {
		return fmt.Errorf("could not neuter child key: %v", err)
	}

	// Print the address too.
	hash160 := btcutil.Hash160(pubKey.SerializeCompressed())
	addrP2PKH, err := btcutil.NewAddressPubKeyHash(hash160, chainParams)
	if err != nil {
		return fmt.Errorf("could not create address: %v", err)
	}
	addrP2WKH, err := btcutil.NewAddressWitnessPubKeyHash(
		hash160, chainParams,
	)
	if err != nil {
		return fmt.Errorf("could not create address: %v", err)
	}

	privKey, xPriv := na, na
	if !neuter {
		privKey, xPriv = wif.String(), child.String()
	}

	result := fmt.Sprintf(
		deriveKeyFormat, path, chainParams.Name,
		pubKey.SerializeCompressed(), neutered, addrP2WKH, addrP2PKH,
		privKey, xPriv,
	)
	fmt.Println(result)

	// For the tests, also log as trace level which is disabled by default.
	log.Tracef(result)

	return nil
}
