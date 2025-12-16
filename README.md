## Silent Payments Developer Dashboard

This dashboard tracks the current state of development across the Silent Payments ecosystem, helping contributors quickly find projects, understand their status, and get involved.

> 💡 **Legend**
> ✅ Complete & working | ⚙️ In Progress | 🆘 Help Wanted | ⛔ Blocked | 🧪 Experimental | ❌ Not Available

---

### Docs & Community

| Project                                                                                                        | Description               | Status | Lead                                             |
| -------------------------------------------------------------------------------------------------------------- | ------------------------- | ------ | ------------------------------------------------ |
| **[BIP-352](https://github.com/bitcoin/bips/blob/master/bip-0352.mediawiki)**                               | Silent payments BIP       | ✅     | [josibake](https://github.com/josibake)             |
| **[Silent payments UX](https://bitcoin.design/guide/how-it-works/silent-payments/)**                        | Bitcoin Design Guide page | ✅     | [yashrajd](https://github.com/yashrajd)             |
| **[Central Hub](https://silentpayments.xyz/)**                                                              | Silent Payments           | ⚙️   | [sethforprivacy](https://github.com/sethforprivacy) |
| **[Tracker](https://docs.google.com/spreadsheets/d/1dXCiAF37UUDs6Hv8jtdQAqfZG6EpwURwCcTk90qnU8g)**          | Development Status        | ⚙️   | macgyver13                                       |
| **[Roadmap](https://docs.google.com/document/d/1ggtPmJWvPCzSoAw0slX4indRDsbm4reDeMjBXreCAzs/edit?tab=t.0)** | Strategy Overview         | ⚙️   | macgyver13                                       |
| **[Discord Server](https://discord.gg/UFF2u6hxBf)**                                                         | Dev coordination hub      | ✅     | yashraj                                          |

---

### Core Cryptography

| Component                  | Description                                  | Status           | Lead / Contact                   | Links                                                        |
| -------------------------- | -------------------------------------------- | ---------------- | -------------------------------- | ------------------------------------------------------------ |
| `libsecp256k1` SP module | Cryptographic primitives for Silent Payments | ⚙️ In Progress | @thestack                        | [PR #1765](https://github.com/bitcoin-core/secp256k1#1765)      |
| Bitcoin Core (352 tracker) | SP wallet support in Bitcoin Core            | ⚙️ In Progress | @josibake / @eunovo              | [Issue #28536](https://github.com/bitcoin/bitcoin/issues/28536) |
| BDK                        | SP wallet support in BDK                     | ⚙️             | [nymius](https://github.com/nymius) | [develop](https://github.com/bitcoindevkit/bdk-sp)              |

---

### Wallet Integrations

| Wallet                     | Send | Receive | Status     | Lead / Contact                           | Notes                                                   |
| -------------------------- | ---- | ------- | ---------- | ---------------------------------------- | ------------------------------------------------------- |
| **BlindBit-Desktop** | ✅   | ✅      | ✅         | [setavenger](https://github.com/setavenger) | Stable                                                  |
| **Cake Wallet**      | ✅   | ✅      | ✅         | Cake Team                                | Stable                                                  |
| **Dana wallet**      | ✅   | ✅      | ✅         | [cygnet](https://github.com/cygnet3)        | Stable                                                  |
| **Sparrow**          | ✅   | ⚙️    | ✅ Partial | [craigraw](https://github.com/craigraw)     | Stable                                                  |
| **BitBox02**         | ✅   | ⚙️    | ✅ Partial | ShiftCrypto                              | Send-only                                               |
| **BlueWallet**       | ✅   | ⚙️    | ✅ Partial | Overtorment                              | Send-only                                               |
| **Bitcoin Core**     | 🧪   | 🧪      | ⛔         | @josibake / @eunovo                      | Blocked on libsecp256k1                                 |
| **Electrum**         | ⚙️ | ❌      | 🧪         | [MorenoProg](https://github.com/MorenoProg) | [PR #9900](https://github.com/spesmilo/electrum/pull/9900) |

---

### Indexers & Servers

| Project                        | Description                     | Status | Lead        | Links / Notes                                                                  |
| ------------------------------ | ------------------------------- | ------ | ----------- | ------------------------------------------------------------------------------ |
| **BlindBit Oracle**      | Full-stack SP Tweak Indexer     | ✅     | @setavenger | [Repo](https://github.com/setavenger/blindbit-oracle)                             |
| **Cake's Esplora fork**  | Electrum based SP Tweak Service | ✅     | ?           | [Cake fork](https://github.com/cake-tech/blockstream-electrs/tree/cake-update-v1) |
| **Frigate**              | experimental Electrum Server    | ✅     | @craigraw   | [Repo](https://github.com/sparrowwallet/frigate)                                  |
| **Electrs**              | SP tweaks in Electrs            | 🧪     | @romanz     | [PR 1075](https://github.com/romanz/electrs/pull/1075)                            |
| **Bitcoin Index Server** | SP tweak consistency            | 🧪     | @sjors      | [PR #86](https://github.com/Sjors/bitcoin/pull/86)                                |

---

### Protocol & Spec

| Topic                             | Description                | Status  | Lead / Contact | Notes                                                                                     |
| --------------------------------- | -------------------------- | ------- | -------------- | ----------------------------------------------------------------------------------------- |
| **Indexing Server Spec**    | Receiving Service Proposal | ⚙️    | @macgyver13    | [Server Spec](https://github.com/silent-payments/BIP0352-index-server-specification)         |
| **Light Client Protocol**   | Fetch tweaks from server   | 🧪 / 🆘 | @setavenger    | [Delving Discussion](https://delvingbitcoin.org/t/silent-payments-light-client-protocol/891) |
| PSBTv2 + Silent Payments          | BIP 375                    | ✅      | @josibake      | [BIP 375](https://github.com/bitcoin/bips/blob/master/bip-0375.mediawiki)                    |
| Silent Payments Output Descriptor | Format Proposal            | ⚙️    | @craigraw      | [BIP sp() output descriptor](https://github.com/bitcoin/bips/pull/2047)                      |
| Add PSBT_IN_SP_TWEAK field        | new PSBT field for SP      | ⚙️    | @nymius        | [Proposal](https://gist.github.com/nymius/b3dd0b8a08c6735d617e6216b73c4260)                  |

---

### Testing & Evaluation

[Tested App / User Guides](https://macgyver13.github.io/app-tester/output/)

#### Tools

* [regtest silent payments faucet](https://silentpayments.dev/faucet/regtest/)
* [signet silent payments faucet](https://silentpayments.dev/faucet/signet/)
* [tweak service auditor](https://github.com/silent-payments/tweak-service-auditor)

#### Setup Guides

* [blindbit-oracle](testing/blindbit-oracle.md)
* [bluewallet](testing/bluewallet.md)
* [seedsigner](testing/seedsigner.md)

---

#### Vectors

| Area             | Project                                                                                                                                   |
| ---------------- | ----------------------------------------------------------------------------------------------------------------------------------------- |
| Address Encoding | [bdk-sp](https://github.com/bitcoindevkit/bdk-sp/blob/3842af15d0bf3440e357ee17ca02a2cef74af60d/silentpayments/src/encoding/mod.rs#L179-L279) |
| Send + Receive   | [BIP352](https://github.com/bitcoin/bips/blob/master/bip-0352/send_and_receive_test_vectors.json)                                            |

### Reference & Education

* [BIP375 examples](https://github.com/macgyver13/bip375-examples) PSBTv2
  * Wallet (HW Air Gap) signing - python & rust
  * Multi-party signing - python & rust
  * PSBT viewer - rust
