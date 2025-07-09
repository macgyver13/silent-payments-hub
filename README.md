## Silent Payments Developer Dashboard

This dashboard tracks the current state of development across the Silent Payments ecosystem, helping contributors quickly find projects, understand their status, and get involved.

> 💡 **Legend**
> ✅ Complete & working | ⚙️ In Progress | 🆘 Help Wanted | ⛔ Blocked | 🧪 Experimental | ❌ Not Available

---

### Docs & Community

| Project | Description | Status | Lead
|--------|-------------|--------|------|
| **[BIP-352](https://github.com/bitcoin/bips/blob/master/bip-0352.mediawiki)** | Silent payments BIP | ✅ | [josibake](https://github.com/josibake) 
| **[Silent payments UX](https://bitcoin.design/guide/how-it-works/silent-payments/)** | Bitcoin Design Guide page | ✅ | [yashrajd](https://github.com/yashrajd) 
| **[Central Hub](https://silentpayments.xyz/)** | Silent Payments | ⚙️ | [sethforprivacy](https://github.com/sethforprivacy)
| **[Tracker](https://docs.google.com/spreadsheets/d/1dXCiAF37UUDs6Hv8jtdQAqfZG6EpwURwCcTk90qnU8g)** | Development Status | ⚙️ | macgyver13
| **[Roadmap](https://docs.google.com/document/d/1ggtPmJWvPCzSoAw0slX4indRDsbm4reDeMjBXreCAzs/edit?tab=t.0)** | Strategy Overview | ⚙️ | macgyver13
| **[Discord Server](https://discord.gg/UFF2u6hxBf)** | Dev coordination hub | ✅ | yashraj

---

### Core Cryptography

| Component | Description | Status | Lead / Contact | Links |
|----------|-------------|--------|----------------|-------|
| `libsecp256k1` SP module | Cryptographic primitives for Silent Payments | ⚙️ In Progress | @josibake | [PR #1519](https://github.com/bitcoin-core/secp256k1/pull/1519) |
| Bitcoin Core (send/receive) | SP wallet support in Bitcoin Core | ⛔ Blocked (on above) | @josibake / @eunovo | [Issue #28536](https://github.com/bitcoin/bitcoin/issues/28536) |
| BDK | SP wallet support in BDK | 🧪 | [nymius](https://github.com/nymius) | [develop](https://github.com/bitcoindevkit/bdk-sp) |

---

### Wallet Integrations

| Wallet | Send | Receive | Status | Lead / Contact | Notes |
|--------|------|---------|--------|----------------|-------|
| **Sparrow** |  🆘 |  🆘 | 🆘 | Open | Needs indexer coordination |
| **BitBox02** | ✅ | ❌ | ✅ Partial | ShiftCrypto | Send-only |
| **Cake Wallet** | ✅ | ✅ | ✅ | Cake Team |  |
| **BlueWallet** | ✅ | ❌ | ✅ Partial | Overtorment | Experimental branch |
| **Bitcoin Core** | ⚙️ | ⛔ | ⛔ | @josibake / @eunovo | Blocked on libsecp256k1 |
| **Dana wallet** | ✅ | ✅ | 🧪 | [cygnet](https://github.com/cygnet3) |  |
| **BlindBit** | ✅ | ✅ | 🧪 | [setavenger](https://github.com/setavenger) | Full Stack + Indexing |

---

### Indexers & Servers

| Project | Description | Status | Lead | Links / Notes |
|---------|-------------|--------|------|----------------|
| **BlindBit Oracle** | Full-stack SP proof of concept | 🧪 | @setavenger | [Repo](https://github.com/setavenger/blindbit-oracle) |
| **Electrs** | SP tweaks in Electrs | ⚙️ | @romanz| [PR 1075](https://github.com/romanz/electrs/pull/1075) |
| **Cake's Esplora fork** | Heavy index, possible SP support | 🧪 | ? | [Cake fork](https://github.com/cake-tech/blockstream-electrs/tree/cake-update-v1) |

---

### Protocol & Spec

| Topic | Description | Status | Lead / Contact | Notes |
|-------|-------------|--------|----------------|-------|
| **Light Client Protocol** | Fetch tweaks from server | 🧪 / 🆘 | @setavenger | [Delving Discussion](https://delvingbitcoin.org/t/silent-payments-light-client-protocol/891) |

---

### Testing & Evaluation

* [blindbit-oracle](testing/blindbit-oracle.md)
* [bluewallet](testing/bluewallet.md)
* [seedsigner](testing/seedsigner.md)

---

#### Vectors

| Area | Project |
|------|---------|
| Address Encoding | [bdk-sp](https://github.com/bitcoindevkit/bdk-sp/blob/3842af15d0bf3440e357ee17ca02a2cef74af60d/silentpayments/src/encoding/mod.rs#L179-L279) |
| Send + Receive | [BIP352](https://github.com/bitcoin/bips/blob/master/bip-0352/send_and_receive_test_vectors.json) |

