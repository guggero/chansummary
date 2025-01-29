# Channel tools

## Index

* [Installation](#installation)
* [Channel recovery scenario](#channel-recovery-scenario)
* [Seed and passphrase input](#seed-and-passphrase-input)
* [Command overview](#command-overview)
* [Commands](#commands)

This tool provides helper functions that can be used to rescue funds locked in
`lnd` channels in case `lnd` itself cannot run properly anymore.

**WARNING**: This tool was specifically built for a certain rescue operation and
might not be well-suited for your use case. Or not all edge cases for your needs
are coded properly. Please look at the code to understand what it does before
you use it for anything serious.

**WARNING 2**: This tool will query public block explorer APIs for some
commands, your privacy might not be preserved. Use at your own risk or supply
a private API URL with `--apiurl`.

## Installation

The easiest way to install `chantools` is to [download a pre-built binary for
your operating system and
architecture](https://github.com/lightninglabs/chantools/releases).

Example (make sure you always use the latest version!):

```shell
$ cd /tmp
$ wget -O chantools.tar.gz https://github.com/lightninglabs/chantools/releases/download/v0.13.4/chantools-linux-amd64-v0.13.4.tar.gz
$ tar -zxvf chantools.tar.gz
$ sudo mv chantools-*/chantools /usr/local/bin/
```

### Compile from source

If there isn't a pre-built binary for your operating system or architecture
available or you want to build `chantools` from source for another reason, you
need to make sure you have `go 1.22.3` (or later) and `make` installed and can
then run the following commands:

```bash
git clone https://github.com/lightninglabs/chantools.git
cd chantools
make install
```

## When should I use what command?

This list contains a list of scenarios that users seem to run into sometimes.

**Before you start running any `chantools` command, you MUST read the
["What should I NEVER do?"](#what-should-i-never-do) section below!**

Scenarios:

- **My node/disk/database crashed and I only have the seed and `channel.backup`
  file.**

  This is the "normal" recovery scenario for which you don't need `chantools`.
  Just follow the [`lnd` recovery guide][recovery].
  All channels will be closed to recover funds, so you should still try to avoid
  This scenario. You only need `chantools` if you had [zombie
  channels][safety-zombie] or a channel that did not confirm in time (see
  below).

- **My node/disk/database crashed and I only have the seed.**

  This is very bad and recovery will take manual steps and might not be
  successful for private channels. If you do not have _any_ data left from your
  node, you need to follow the [`chantools fakechanbackup` command
  ](doc/chantools_fakechanbackup.md) help text. If you do have an old version of
  your `channel.db` file, DO NOT UNDER ANY CIRCUMSTANCES start your node with
  it. Instead, try to extract a `channel.backup` from it using the [`chantools
  chanbackup`](doc/chantools_chanbackup.md) command. If that is successful,
  follow the steps in the [`lnd` recovery guide][recovery].
  This will not cover new channels opened after the backup of the `channel.db`
  file was created. You might still need to create the fake channel backup.

- **I suspect my channel.db file to be corrupt.**

  This can happen due to unclean shutdowns or power outages. Try running
  [`chantools compactdb`](doc/chantools_compactdb.md). If there are NO ERRORS
  during the execution of that command, things should be back to normal, and you
  can continue running your node. If you get errors, you should probably follow
  the [recovery scenario described below](#channel-recovery-scenario) to avoid
  future issues. This will close all channels, however.

- **I don't have a `channel.backup` file but all my peers force closed my
  channels, why don't I see the funds with just my seed?**

  When a channel is force closed by the remote party, the funds don't
  automatically go to a normal on-chain address. You need to sweep those funds
  using the [`chantools sweepremoteclosed`](doc/chantools_sweepremoteclosed.md)
  command.

- **My channel peer is online, but they don't force close a channel when using
  a `channel.backup` file**.

  This can have many reasons. Often it means the channels is a legacy channel
  type (not an anchor output channel) and the force close transaction the peer
  has doesn't have enough fees to make it into the mempool. In that case waiting
  for an empty mempool might be the only option.
  Another reason might be that the peer is a CLN node with a specific version
  that doesn't react to force close requests normally. You can use the
  [`chantools triggerforceclose` command](doc/chantools_triggerforceclose.md) in
  that case (should work with CLN peers of a certain version that don't respond
  to normal force close requests).

## What should I NEVER do?

- You should never panic. There are extremely few situations in which doing
  nothing makes things worse. On the contrary, most cases where users actually
  lost funds it was due to them running commands they did not understand in a
  rush of panic. So stay calm, try to find out what the reason for the problem
  is, ask for help (see [Slack][slack], [`lnd` discussions][discussions]) or use
  Google.
  Create a backup of all your files in the `lnd` data directory (just in case,
  but never [start a node from a file based backup][safety-file-backup])
  before running _any_ command. Also read the [`lnd` Operational Safety
  Guidelines][safety].
- Whatever you might read in any issue, you should never use
  `lncli abandonchannel` on a channel that was confirmed on chain. Even if you
  have an SCB (Static Channel Backup, unfortunately poorly named) file
  (`channel.backup`) or export from `lncli exportchanbackup`. Those files DO NOT
  contain enough information to close a channel if your peer does not have the
  channel data either (which might happen if the channel took longer than 2
  weeks to confirm). If the channel confirmed on chain, you need to force close
  it from your node if it does not operate normally. Running `abandonchannel`
  deletes the information needed to be able to force close.
- When running Umbrel, NEVER just uninstall the Lightning App when encountering
  a problem. Uninstalling the app deletes important data that might be needed
  for recovery in edge cases. The channel backup (SCB) in the cloud does NOT
  cover "expired" channels (channels that took longer than 2 weeks to confirm)
  or [zombie channels][safety-zombie].
- The term "backup" in SCB (Static Channel Backup) or the `channel.backup` file
  or the output of `lncli exportchanbackup` is not optimal as it implies the
  channels can be fully restored or brought back to an operational state. But
  the content of those files are for absolute emergencies only. Channels are
  always closed when using such a file (by asking the remote peer to issue their
  latest force close transaction they have). So chain fees occur. And there are
  some edge cases where funds are not covered by those files, for example when
  a channel funding transaction is not confirmed in time. Or for channels where
  the peer is no longer online. So deleting your `lnd` data directory should
  never ever be something to be done lightly (see Umbrel above).

## Channel recovery scenario

The following flow chart shows the main recovery scenario this tool was built
for. This scenario assumes that you do have access to the crashed node's seed,
`channel.backup` file and some state of a `channel.db` file (perhaps from a
file based backup or the recovered file from the crashed node).

Following this guide will help you get your channel **funds** back! The channels
themselves can't be restored to work normally unless step 1 is successful (
compacting the DB).

![rescue flow](doc/rescue-flow.png)

**Explanation:**

1. **Node crashed**: For some reason your `lnd` node crashed and isn't starting
   anymore. If you get errors similar to
   [this](https://github.com/lightningnetwork/lnd/issues/4449),
   [this](https://github.com/lightningnetwork/lnd/issues/3473) or
   [this](https://github.com/lightningnetwork/lnd/issues/4102), it is possible
   that a simple compaction (a full copy in safe mode) can solve your problem.
   See [`chantools compactdb`](doc/chantools_compactdb.md).
   <br/><br/>
   If that doesn't work and you need to continue the recovery, make sure you can
   at least extract the `channel.backup` file and if somehow possible any
   version
   of the `channel.db` from the node.
   <br/><br/>
   Whatever you do, do **never, ever** replace your `channel.db` file with an
   old
   version (from a file based backup) and start your node that way.
   [Read this explanation why that can lead to loss of
   funds.][safety-file-backup]

2. **Rescue on-chain balance**: To start the recovery process, we are going to
   re-create the node from scratch. To make sure we don't overwrite any old data
   in the process, make sure the old data directory of your node (usually `.lnd`
   in the user's home directory) is safely moved away (or the whole folder
   renamed) before continuing.<br/>
   To start the on-chain recovery, [follow the sub step "Starting On-Chain
   Recovery" of this guide][recovery].
   Don't follow the whole guide, only this single chapter!
   <br/><br/>
   This step is completed once the `lncli getinfo` command shows both
   `"synced_to_chain": true` and `"synced_to_graph": true` which can take
   several
   hours depending on the speed of your hardware. **Do not be alarmed** that the
   `lncli getinfo` command shows 0 channels. This is normal as we haven't
   started
   the off-chain recovery yet.

3. **Recover channels using SCB**: Now that the node is fully synced, we can try
   to recover the channels using the [Static Channel Backups (SCB)][safety-scb].
   For this, you need a file called `channel.backup`. Simply run the command
   `lncli restorechanbackup --multi_file <path-to-your-channel.backup>`. **This
   will take a while!**. The command itself can take several minutes to
   complete,
   depending on the number of channels. The recovery can easily take a day or
   two as a lot of chain rescanning needs to happen. It is recommended to wait
   at
   least one full day. You can watch the progress with
   the `lncli pendingchannels`
   command. If the list is empty, congratulations, you've recovered all
   channels!
   If the list stays un-changed for several hours, it means not all channels
   could be restored using this method.
   [One explanation can be found here.][safety-zombie]

4. **Install chantools**: To try to recover the remaining channels, we are going
   to use `chantools`.
   Simply [follow the installation instructions.](#installation)
   The recovery can only be continued if you have access to some version of the
   crashed node's `channel.db`. This could be the latest state as recovered from
   the crashed file system, or a version from a regular file based backup. If
   you
   do not have any version of a channel DB, `chantools` won't be able to help
   with the recovery. See step 11 for some possible manual steps.

5. **Create copy of channel DB**: To make sure we can read the channel DB, we
   are going to create a copy in safe mode (called compaction). Simply run
   <br/><br/>
   `chantools compactdb --sourcedb <recovered-channel.db> --destdb ./results/compacted.db`
   <br/><br/>
   We are going to assume that the compacted copy of the channel DB is located
   in
   `./results/compacted.db` in the following commands.

6. **chantools summary**: First, `chantools` needs to find out the state of each
   channel on chain. For this, a blockchain API (by
   default [node-recovery.com](https://api.node-recovery.com))
   is queried. The result will be written to a file called
   `./results/summary-yyyy-mm-dd.json`. This result file will be needed for the
   next command.
   <br/><br/>
   `chantools --fromchanneldb ./results/compacted.db summary`

7. **chantools rescueclosed**: It is possible that by now the remote peers have
   force-closed some of the remaining channels. What we now do is try to find
   the
   private keys to sweep our balance of those channels. For this we need a
   shared
   secret which is called the `commit_point` and is changed whenever a channel
   is
   updated. We do have the latest known version of this point in the channel DB.
   The following command tries to find all private keys for channels that have
   been closed by the other party. The command needs to know what channels it is
   operating on, so we have to supply the `summary-yyy-mm-dd.json` created by
   the
   previous command:
   <br/><br/>
   `chantools --fromsummary ./results/<summary-file-created-in-last-step>.json rescueclosed --channeldb ./results/compacted.db`
   <br/><br/>
   This will create a new file called `./results/rescueclosed-yyyy-mm-dd.json`
   which will contain any found private keys and will also be needed for the
   next
   command. Use `bitcoind` or Electrum Wallet to sweep all of the private keys.

8. **chantools forceclose**: This command will now close all channels that
   `chantools` thinks are still open. This is achieved by publishing the latest
   known channel state of the `channel.db` file.
   <br/>**Please read the full warning text of the
   [`forceclose` command below](doc/chantools_forceclose.md) as this command can
   put
   your funds at risk** if the state in the channel DB is not the most recent
   one. This command should only be executed for channels where the remote peer
   is not online anymore.
   <br/><br/>
   `chantools --fromsummary ./results/<rescueclosed-file-created-in-last-step>.json forceclose --channeldb ./results/compacted.db --publish`
   <br/><br/>
   This will create a new file called `./results/forceclose-yyyy-mm-dd.json`
   which will be needed for the next command.
   <br/><br/>
   If you get the
   error `non-mandatory-script-verify-flag (Signature must be zero
   for failed CHECK(MULTI)SIG operation)`, you might be affected by an old bug
   of `lnd` that was fixed in the meantime. But it means the signature in the
   force-close transaction is invalid and needs to be fixed. There is [a guide
   on how to do exactly that here](doc/fix-commitment-tx.md).

9. **Wait for timelocks**: The previous command closed the remaining open
   channels by publishing your node's state of the channel. By design of the
   Lightning Network, you now have to wait until the channel funds belonging to
   you are not time locked any longer. Depending on the size of the channel, you
   have to wait for somewhere between 144 and 2000 confirmations of the
   force-close transactions. Only continue with the next step after the channel
   with the highest `csv_delay` has reached that many confirmations of its
   closing transaction. You can check this by looking up each force closed
   channel transaction on a block explorer (like
   [blockstream.info](https://blockstream.info) for example). Open the result
   JSON file of the last command (`./results/forceclose-yyyy-mm-dd.json`) and
   look up every TXID in `"force_close" -> "txid"` on the explorer. If the
   number
   of confirmations is equal to or greater to the value shown in
   `"force_close" -> "csv_delay"` for each of the channels, you can proceed.

10. **chantools sweeptimelock**: Once all force-close transactions have reached
    the number of transactions as the `csv_timeout` in the JSON demands, these
    time locked funds can now be swept. Use the following command to sweep all
    the
    channel funds to an address of your wallet:
    <br/><br/>
    `chantools --fromsummary ./results/<forceclose-file-created-in-last-step>.json sweeptimelock --publish --sweepaddr <bech32-address-from-your-wallet>`

11. **Manual intervention necessary**: You got to this step because you either
    don't have a `channel.db` file or because `chantools` couldn't rescue all
    your
    node's channels. There are a few things you can try manually that have some
    chance of working:
    - Make sure you can connect to all nodes when restoring from SCB: It happens
      all the time that nodes change their IP addresses. When restoring from a
      static channel backup, your node tries to connect to the node using the IP
      address encoded in the backup file. If the address changed, the SCB
      restore
      process doesn't work. You can use block explorers
      like [1ml.com](https://1ml.com)
      to try to find an IP address that is up-to-date. Just run
      `lncli connect <node-pubkey>@<updated-ip-address>:<port>` in the recovered
      `lnd` node from step 3 and wait a few hours to see if the channel is now
      being force closed by the remote node.
    - Find out who the node belongs to: Maybe you opened the channel with
      someone
      you know. Or maybe their node alias contains some information about who
      the
      node belongs to. If you can find out who operates the remote node, you can
      ask them to force-close the channel from their end. If the channel was
      opened
      with the `option_static_remote_key`, (`lnd v0.8.0` and later), the funds
      can
      be swept by your node.

12. **Use Zombie Channel Recovery Matcher**: As a final, last resort, you can
    go to [node-recovery.com](https://www.node-recovery.com/) and register your
    node's ID for being matched up against other nodes with the same problem.
    <br/><br/>
    Once you were contacted with a match, follow the instructions on the
    [Zombie Channel Recovery Guide](doc/zombierecovery.md) page.
    <br/><br/>
    If you know the peer of a zombie channel and have a way to contact them, you
    can also skip the registration/matching process and [create your own match
    file](doc/zombierecovery.md#file-format).

## Seed and passphrase input

All commands that require the seed (and, if set, the seed's passphrase) offer
three distinct possibilities to specify it:

1. **Enter manually on the terminal**: This is the safest option as it makes
   sure that the seed isn't stored in the terminal's command history.
2. **Pass the extened master root key as parameter**: This is added as an option
   for users who don't have the full seed anymore, possibly because they used
   `lnd`'s `--noseedbackup` flag and extracted the `xprv` from the wallet
   database with the `walletinfo` command. Those users can specify the master
   root key by passing the `--rootkey` command line flag to each command that
   requires the seed.
3. **Use environment variables**: This option makes it easy to automate usage of
   `chantools` by removing the need to type into the terminal. There are three
   environment variables that can be set to skip entering values through the
   terminal:
    - `AEZEED_MNEMONIC`: Specifies the 24 word `lnd` aezeed.
    - `AEZEED_PASSPHRASE`: Specifies the passphrase for the aezeed. If no
      passphrase was used during the creation of the seed, the special value
      `AEZEED_PASSPHRASE="-"` needs to be passed to indicate no passphrase
      should be used or read from the terminal.
    - `WALLET_PASSWORD`: Specifies the encryption password that is needed to
      access a `wallet.db` file. This is currently only used by the `walletinfo`
      command.

Example using environment variables:

```shell script
# We add a space in front of each command to tell bash we don't want this
# command stored in the history.
$    export AEZEED_MNEMONIC="abandon able ... ... ..."
# We didn't set a passphrase for this example seed, we need to indicate this by
# passing in a single dash character.
$    export AEZEED_PASSPHRASE="-"
$ chantools showrootkey

2020-10-29 20:22:42.329 [INF] CHAN: chantools version v0.12.0 commit v0.12.0

Your BIP32 HD root key is: xprv9s21ZrQH1...
```

### Are my funds safe?

Some commands require the seed. But your seed will never leave your computer.

Most commands don't require an internet connection: you can and should
run them on a computer with a firewall that blocks outgoing connections.

## Command overview

```text
This tool provides helper functions that can be used rescue
funds locked in lnd channels in case lnd itself cannot run properly anymore.
Complete documentation is available at
https://github.com/lightninglabs/chantools/.

Usage:
  chantools [command]

Available Commands:
  chanbackup          Create a channel.backup file from a channel database
  closepoolaccount    Tries to close a Pool account that has expired
  createwallet        Create a new lnd compatible wallet.db file from an existing seed or by generating a new one
  compactdb           Create a copy of a channel.db file in safe/read-only mode
  deletepayments      Remove all (failed) payments from a channel DB
  derivekey           Derive a key with a specific derivation path
  doublespendinputs   Replace a transaction by double spending its input
  dropchannelgraph    Remove all graph related data from a channel DB
  dropgraphzombies    Remove all channels identified as zombies from the graph to force a re-sync of the graph
  dumpbackup          Dump the content of a channel.backup file
  dumpchannels        Dump all channel information from an lnd channel database
  dropheighthintcache Remove all height hint cache data from the channel DB.
  fakechanbackup      Fake a channel backup file to attempt fund recovery
  filterbackup        Filter an lnd channel.backup file and remove certain channels
  fixoldbackup        Fixes an old channel.backup file that is affected by the lnd issue #3881 (unable to derive shachain root key)
  forceclose          Force-close the last state that is in the channel.db provided
  genimportscript     Generate a script containing the on-chain keys of an lnd wallet that can be imported into other software like bitcoind
  migratedb           Apply all recent lnd channel database migrations
  pullanchor          Attempt to CPFP an anchor output of a channel
  recoverloopin       Recover a loop in swap that the loop daemon is not able to sweep
  removechannel       Remove a single channel from the given channel DB
  rescueclosed        Try finding the private keys for funds that are in outputs of remotely force-closed channels
  rescuefunding       Rescue funds locked in a funding multisig output that never resulted in a proper channel; this is the command the initiator of the channel needs to run
  rescuetweakedkey    Attempt to rescue funds locked in an address with a key that was affected by a specific bug in lnd
  showrootkey         Extract and show the BIP32 HD root key from the 24 word lnd aezeed
  signmessage         Sign a message with the node's private key.
  signrescuefunding   Rescue funds locked in a funding multisig output that never resulted in a proper channel; this is the command the remote node (the non-initiator) of the channel needs to run
  signpsbt            Sign a Partially Signed Bitcoin Transaction (PSBT)
  summary             Compile a summary about the current state of channels
  sweeptimelock       Sweep the force-closed state after the time lock has expired
  sweeptimelockmanual Sweep the force-closed state of a single channel manually if only a channel backup file is available
  sweepremoteclosed   Go through all the addresses that could have funds of channels that were force-closed by the remote party. A public block explorer is queried for each address and if any balance is found, all funds are swept to a given address
  triggerforceclose   Connect to a Lightning Network peer and send specific messages to trigger a force close of the specified channel
  vanitygen           Generate a seed with a custom lnd node identity public key that starts with the given prefix
  walletinfo          Shows info about an lnd wallet.db file and optionally extracts the BIP32 HD root key
  zombierecovery      Try rescuing funds stuck in channels with zombie nodes
  help                Help about any command

Flags:
  -h, --help      help for chantools
  -r, --regtest   Indicates if regtest parameters should be used
  -s, --signet    Indicates if the public signet parameters should be used
  -t, --testnet   Indicates if testnet parameters should be used
  -v, --version   version for chantools

Use "chantools [command] --help" for more information about a command.
```

## Commands

Detailed documentation for each sub command is available in the
[docs](doc/chantools.md) folder.

The following table provides quick access to each command's documentation.
Legend:

- :pencil: This command requires the seed to be entered (see [seed and
  passphrase input](#seed-and-passphrase-input)).
- :warning: Should not be used unless no other option exists, can lead to
  malfunction of the node.
- :skull: Danger of loss of funds, only use when instructed to.
- :pushpin: Command was created for a very specific version or use case and most
  likely does not apply to 99.9% of users

| Command                                                     | Use when                                                                                                                                 |
|-------------------------------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------|
| [chanbackup](doc/chantools_chanbackup.md)                   | :pencil: Extract a `channel.backup` file from a `channel.db` file                                                                        |
| [closepoolaccount](doc/chantools_closepoolaccount.md)       | :pencil: Manually close an expired Lightning Pool account                                                                                |
| [compactdb](doc/chantools_compactdb.md)                     | Run database compaction manually to reclaim space                                                                                        |
| [createwallet](doc/chantools_createwallet.md)               | :pencil: Create a new lnd compatible wallet.db file from an existing seed or by generating a new one                                     |
| [deletepayments](doc/chantools_deletepayments.md)           | Remove ALL payments from a `channel.db` file to reduce size                                                                              |
| [derivekey](doc/chantools_derivekey.md)                     | :pencil: Derive a single private/public key from `lnd`'s seed, use to test seed                                                          |
| [doublespendinputs](doc/chantools_doublespendinputs.md)     | :pencil: Tries to double spend the given inputs by deriving the private for the address and sweeping the funds to the given address      |
| [dropchannelgraph](doc/chantools_dropchannelgraph.md)       | (:warning:) Completely drop the channel graph from a `channel.db` to force re-sync                                                       |
| [dropgraphzombies](doc/chantools_dropgraphzombies.md)       | Drop all zombie channels from a `channel.db` to force a graph re-sync                                                                    |
| [dumpbackup](doc/chantools_dumpbackup.md)                   | :pencil: Show the content of a `channel.backup` file as text                                                                             |
| [dumpchannels](doc/chantools_dumpchannels.md)               | Show the content of a `channel.db` file as text                                                                                          |
| [fakechanbackup](doc/chantools_fakechanbackup.md)           | :pencil: Create a fake `channel.backup` file from public information                                                                     |
| [filterbackup](doc/chantools_filterbackup.md)               | :pencil: Remove a channel from a `channel.backup` file                                                                                   |
| [fixoldbackup](doc/chantools_fixoldbackup.md)               | :pencil: (:pushpin:) Fixes an issue with old `channel.backup` files                                                                      |
| [forceclose](doc/chantools_forceclose.md)                   | :pencil: (:skull: :warning:) Publish an old channel state from a `channel.db` file                                                       |
| [genimportscript](doc/chantools_genimportscript.md)         | :pencil: Create a script/text file that can be used to import `lnd` keys into other software                                             |
| [migratedb](doc/chantools_migratedb.md)                     | Upgrade the `channel.db` file to the latest version                                                                                      |
| [pullanchor](doc/chantools_pullanchor.md)                   | :pencil: Attempt to CPFP an anchor output of a channel                                                                                   | 
| [recoverloopin](doc/chantools_recoverloopin.md)             | :pencil: Recover funds from a failed Lightning Loop inbound swap                                                                         |
| [removechannel](doc/chantools_removechannel.md)             | (:skull: :warning:) Remove a single channel from a `channel.db` file                                                                     |
| [rescueclosed](doc/chantools_rescueclosed.md)               | :pencil: (:pushpin:) Rescue funds in a legacy (pre `STATIC_REMOTE_KEY`) channel output                                                   |
| [rescuefunding](doc/chantools_rescuefunding.md)             | :pencil: (:pushpin:) Rescue funds from a funding transaction. Deprecated, use [zombierecovery](doc/chantools_zombierecovery.md) instead  |
| [showrootkey](doc/chantools_showrootkey.md)                 | :pencil: Display the master root key (`xprv`) from your seed (DO NOT SHARE WITH ANYONE)                                                  |
| [signmessage](doc/chantools_signmessage.md)                 | :pencil: Sign a message with the nodes identity pubkey.                                                                                  |
| [signpsbt](doc/chantools_signpsbt.md)                       | :pencil: Sign a Partially Signed Bitcoin Transaction (PSBT)                                                                              |
| [signrescuefunding](doc/chantools_signrescuefunding.md)     | :pencil: (:pushpin:) Sign to funds from a funding transaction. Deprecated, use [zombierecovery](doc/chantools_zombierecovery.md) instead |
| [summary](doc/chantools_summary.md)                         | Create a summary of channel funds from a `channel.db` file                                                                               |
| [sweepremoteclosed](doc/chantools_sweepremoteclosed.md)     | :pencil: Find channel funds from remotely force closed channels and sweep them                                                           |
| [sweeptimelock](doc/chantools_sweeptimelock.md)             | :pencil: Sweep funds in locally force closed channels once time lock has expired (requires `channel.db`)                                 |
| [sweeptimelockmanual](doc/chantools_sweeptimelockmanual.md) | :pencil: Manually sweep funds in a locally force closed channel where no `channel.db` file is available                                  |
| [triggerforceclose](doc/chantools_triggerforceclose.md)     | :pencil: (:pushpin:) Request a peer to force close a channel                                                                             |
| [vanitygen](doc/chantools_vanitygen.md)                     | Generate an `lnd` seed for a node public key that starts with a certain sequence of hex digits                                           |
| [walletinfo](doc/chantools_walletinfo.md)                   | Show information from a `wallet.db` file, requires access to the wallet password                                                         |
| [zombierecovery](doc/chantools_zombierecovery.md)           | :pencil: Cooperatively rescue funds from channels where normal recovery is not possible (see [full guide here][zombie-recovery])         |

[safety]: https://github.com/lightningnetwork/lnd/blob/master/docs/safety.md

[safety-zombie]: https://github.com/lightningnetwork/lnd/blob/master/docs/safety.md#zombie-channels

[safety-file-backup]: https://github.com/lightningnetwork/lnd/blob/master/docs/safety.md#file-based-backups

[safety-scb]: https://github.com/lightningnetwork/lnd/blob/master/docs/safety.md#static-channel-backups-scbs

[recovery]: https://github.com/lightningnetwork/lnd/blob/master/docs/recovery.md

[slack]: https://lightning.engineering/slack.html

[discussions]: https://github.com/lightningnetwork/lnd/discussions

[zombie-recovery]: doc/zombierecovery.md
