## Silent Payments Developer Dashboard

This dashboard tracks the current state of development across the Silent Payments ecosystem, helping contributors quickly find projects, understand their status, and get involved.

> 💡 **Legend**
> ✅ Complete & working | ⚙️ In Progress | 🆘 Help Wanted | ⛔ Blocked | 🧪 Experimental | ❌ Not Available

---

### Docs & Community

| Project | Description | Lead |
| --- | ---  | --- |
| **[BIP352](https://github.com/bitcoin/bips/blob/master/bip-0352.mediawiki)** | Silent payments BIP |  [josibake](https://github.com/josibake) |
| **[Silent payments UX](https://bitcoin.design/guide/how-it-works/silent-payments/)** | Bitcoin Design Guide page | [yashrajd](https://github.com/yashrajd) |
| **[Silent Payments Guide](https://bennet.org/learn/silent-payments-bitcoin-privacy/)** | a hands-on guide to better Bitcoin privacy | [bennet](https://bennet.org) |
| **[Central Hub](https://silentpayments.xyz/)** | Silent Payments | [sethforprivacy](https://github.com/sethforprivacy) |
| **[Roadmap](https://github.com/orgs/silent-payments/projects/2)** | Development Status | macgyver13 |
| **[Discord Server](https://discord.gg/UFF2u6hxBf)** | Dev coordination hub | yashraj & macgyver13 |

---

### Core Cryptography

| Component | Description | Status | Lead / Contact | Links |
| --- | --- | --- | --- | --- |
| `libsecp256k1` SP module | Cryptographic primitives for Silent Payments | ⚙️ In Progress | @thestack | [PR #1765](https://github.com/bitcoin-core/secp256k1#1765) |
| Bitcoin Core (352 tracker) | SP wallet support in Bitcoin Core | ⚙️ In Progress | @josibake / @eunovo | [Issue #28536](https://github.com/bitcoin/bitcoin/issues/28536) |
| BDK | SP wallet support in BDK | ⚙️ In Progress | [nymius](https://github.com/nymius) | [bdk-sp](https://github.com/bitcoindevkit/bdk-sp) |

---

### [Wallet Integrations](https://silentpayments.xyz/docs/wallets/#wallets)

---

### [Scanning](https://silentpayments.xyz/docs/developers/#scanning-back-ends)

---

### Protocol & Spec

| Topic | Status  | Lead / Contact | Notes |
| --- | --- | --- | --- |
| **Indexing Server Spec** | ⚙️ | @macgyver13 | [Server Spec](https://github.com/silent-payments/BIP0352-index-server-specification) |
| **Light Client Protocol** | 🧪 / 🆘 | @setavenger | [Delving Discussion](https://delvingbitcoin.org/t/silent-payments-light-client-protocol/891) |
| Sending Silent Payments with PSBTs | ✅ | @josibake | [BIP 375](https://github.com/bitcoin/bips/blob/master/bip-0375.mediawiki) |
| Spending Silent Payment outputs with PSBTs | ✅ | @nymius | [BIP 376](https://github.com/bitcoin/bips/blob/master/bip-0376.mediawiki) |
| Silent Payment Output Script Descriptors | ✅ | @craigraw | [BIP 392](https://github.com/bitcoin/bips/blob/master/bip-0392.mediawiki) |


---

### Testing & Evaluation

[Tested App / User Guides](https://macgyver13.github.io/app-tester/output/)

#### Tools

* [regtest silent payments faucet](https://silentpayments.dev/faucet/regtest/)
* [signet silent payments faucet](https://silentpayments.dev/faucet/signet/)
* [Crypto Toolkit](https://guggero.github.io/cryptography-toolkit/#!/silentpayments)
* [tweak service auditor](https://github.com/silent-payments/tweak-service-auditor)

---

#### Vectors

| Area | Project |
| --- | --- |
| Address Encoding | [bdk-sp](https://github.com/bitcoindevkit/bdk-sp/blob/3842af15d0bf3440e357ee17ca02a2cef74af60d/silentpayments/src/encoding/mod.rs#L179-L279) |
| Send + Receive | [BIP352](https://github.com/bitcoin/bips/blob/master/bip-0352/send_and_receive_test_vectors.json) |
| PSBTv2 + SP | [BIP375](https://github.com/bitcoin/bips/blob/master/bip-0375/bip375_test_vectors.json) |

### Reference & Education

* [BIP375 examples](https://github.com/macgyver13/bip375-examples)
  * Coordinator + HW Air Gap signing - hardware-signer
  * Multi-party signing - multi-signer
  * Musig2 + SP - musig2-signer
  * Frost + SP - frost-signer
  * PSBT viewer
