package main

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/lightninglabs/chantools/btc"
	"github.com/lightninglabs/chantools/lnd"
	"github.com/lightninglabs/chantools/scbforceclose"
	"github.com/lightningnetwork/lnd/chanbackup"
	"github.com/lightningnetwork/lnd/input"
	"github.com/spf13/cobra"
)

type scbForceCloseCommand struct {
	APIURL  string
	Publish bool

	// channel.backup.
	SingleBackup string
	SingleFile   string
	MultiBackup  string
	MultiFile    string

	rootKey *rootKey
	cmd     *cobra.Command
}

func newScbForceCloseCommand() *cobra.Command {
	cc := &scbForceCloseCommand{}
	cc.cmd = &cobra.Command{
		Use: "scbforceclose",
		Short: "Force-close the last state that is in the SCB " +
			"provided",
		Long:    forceCloseWarning,
		Example: `chantools scbforceclose --multi_file channel.backup`,
		RunE:    cc.Execute,
	}
	cc.cmd.Flags().StringVar(
		&cc.APIURL, "apiurl", defaultAPIURL, "API URL to use (must "+
			"be esplora compatible)",
	)

	cc.cmd.Flags().StringVar(
		&cc.SingleBackup, "single_backup", "", "a hex encoded single "+
			"channel backup obtained from exportchanbackup for "+
			"force-closing channels",
	)
	cc.cmd.Flags().StringVar(
		&cc.MultiBackup, "multi_backup", "", "a hex encoded "+
			"multi-channel backup obtained from exportchanbackup "+
			"for force-closing channels",
	)
	cc.cmd.Flags().StringVar(
		&cc.SingleFile, "single_file", "", "the path to a "+
			"single-channel backup file",
	)
	cc.cmd.Flags().StringVar(
		&cc.MultiFile, "multi_file", "", "the path to a "+
			"single-channel backup file (channel.backup)",
	)

	cc.cmd.Flags().BoolVar(
		&cc.Publish, "publish", false, "publish force-closing TX to "+
			"the chain API instead of just printing the TX",
	)

	cc.rootKey = newRootKey(cc.cmd, "decrypting the backup and signing tx")

	return cc.cmd
}

func (c *scbForceCloseCommand) Execute(_ *cobra.Command, _ []string) error {
	extendedKey, err := c.rootKey.read()
	if err != nil {
		return fmt.Errorf("error reading root key: %w", err)
	}

	api := &btc.ExplorerAPI{BaseURL: c.APIURL}

	keyRing := &lnd.HDKeyRing{
		ExtendedKey: extendedKey,
		ChainParams: chainParams,
	}

	signer := &lnd.Signer{
		ExtendedKey: extendedKey,
		ChainParams: chainParams,
	}
	signer.MusigSessionManager = input.NewMusigSessionManager(
		signer.FetchPrivateKey,
	)

	var backups []chanbackup.Single
	if c.SingleBackup != "" || c.SingleFile != "" {
		if c.SingleBackup != "" && c.SingleFile != "" {
			return errors.New("must not pass --single_backup and " +
				"--single_file together")
		}
		var singleBackupBytes []byte
		if c.SingleBackup != "" {
			singleBackupBytes, err = hex.DecodeString(
				c.SingleBackup,
			)
		} else if c.SingleFile != "" {
			singleBackupBytes, err = os.ReadFile(c.SingleFile)
		}
		if err != nil {
			return fmt.Errorf("failed to get single backup: %w",
				err)
		}
		var s chanbackup.Single
		r := bytes.NewReader(singleBackupBytes)
		if err := s.UnpackFromReader(r, keyRing); err != nil {
			return fmt.Errorf("failed to unpack single backup: %w",
				err)
		}
		backups = append(backups, s)
	}
	if c.MultiBackup != "" || c.MultiFile != "" {
		if len(backups) != 0 {
			return errors.New("must not pass single and multi " +
				"backups together")
		}
		if c.MultiBackup != "" && c.MultiFile != "" {
			return errors.New("must not pass --multi_backup and " +
				"--multi_file together")
		}
		var multiBackupBytes []byte
		if c.MultiBackup != "" {
			multiBackupBytes, err = hex.DecodeString(c.MultiBackup)
		} else if c.MultiFile != "" {
			multiBackupBytes, err = os.ReadFile(c.MultiFile)
		}
		if err != nil {
			return fmt.Errorf("failed to get multi backup: %w", err)
		}
		var m chanbackup.Multi
		r := bytes.NewReader(multiBackupBytes)
		if err := m.UnpackFromReader(r, keyRing); err != nil {
			return fmt.Errorf("failed to unpack multi backup: %w",
				err)
		}
		backups = append(backups, m.StaticBackups...)
	}

	backupsWithInputs := make([]chanbackup.Single, 0, len(backups))
	for _, s := range backups {
		if s.CloseTxInputs.IsSome() {
			backupsWithInputs = append(backupsWithInputs, s)
		}
	}

	fmt.Println()
	fmt.Printf("Found %d channel backups, %d of them have close tx.\n",
		len(backups), len(backupsWithInputs))

	if len(backupsWithInputs) == 0 {
		fmt.Println("No channel backups that can be used for force " +
			"close.")
		return nil
	}

	fmt.Println()
	fmt.Println("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@")
	fmt.Println(strings.TrimSpace(forceCloseWarning))
	fmt.Println("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@")
	fmt.Println()

	fmt.Printf("Type YES to proceed: ")
	var userInput string
	if _, err := fmt.Scan(&userInput); err != nil {
		return errors.New("failed to read user input")
	}
	if strings.TrimSpace(userInput) != "YES" {
		return errors.New("canceled by user, must type uppercase 'YES'")
	}

	if c.Publish {
		fmt.Println("Signed transactions will be broadcasted " +
			"automatically.")
		fmt.Printf("Type YES again to proceed: ")
		if _, err := fmt.Scan(&userInput); err != nil {
			return errors.New("failed to read user input")
		}
		if strings.TrimSpace(userInput) != "YES" {
			return errors.New("canceled by user, must type " +
				"uppercase 'YES'")
		}
	}

	for _, s := range backupsWithInputs {
		signedTx, err := scbforceclose.SignCloseTx(
			s, keyRing, signer, signer,
		)
		if err != nil {
			return fmt.Errorf("signCloseTx failed for %s: %w",
				s.FundingOutpoint, err)
		}
		var buf bytes.Buffer
		if err := signedTx.Serialize(&buf); err != nil {
			return fmt.Errorf("failed to serialize signed %s: %w",
				s.FundingOutpoint, err)
		}
		txHex := hex.EncodeToString(buf.Bytes())
		fmt.Println("Channel point:", s.FundingOutpoint)
		fmt.Println("Raw transaction hex:", txHex)
		fmt.Println()

		// Publish TX.
		if c.Publish {
			response, err := api.PublishTx(txHex)
			if err != nil {
				return err
			}
			log.Infof("Published TX %s, response: %s",
				signedTx.TxHash(), response)
		}
	}

	return nil
}
