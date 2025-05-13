## Silent Payments Developer Dashboard

This dashboard tracks the current state of development across the Silent Payments ecosystem, helping contributors quickly find projects, understand their status, and get involved.

> 💡 **Legend**
> ✅ Complete & working | ⚙️ In Progress | 🆘 Help Wanted | ⛔ Blocked | 🧪 Experimental

---

### Docs & Community

| Project | Description | Status | Lead
|--------|-------------|--------|------|
| **[Central Hub](https://silentpayments.xyz/)** | Silent Payments | ⚙️ | @sethforprivacy
| **[Visual Roadmap](diagrams/project_overview.mmd)** | Flowchart of SP ecosystem | ⚙️ | Open
| **[Wallet UX](diagrams/wallet_ux.mmd)** | SP User Flow | ⚙️ | Open
| **[Tracker](https://docs.google.com/spreadsheets/d/1dXCiAF37UUDs6Hv8jtdQAqfZG6EpwURwCcTk90qnU8g/edit)** | Development Status | ⚙️ | @macgyver
| **[Roadmap](https://docs.google.com/document/d/1ggtPmJWvPCzSoAw0slX4indRDsbm4reDeMjBXreCAzs/edit?tab=t.0)** | Strategy Overview | ⚙️ | @macgyver
| **Discord Server** | Dev coordination hub | 🆘 | ? / @yashraj

---

### Core Cryptography

| Component | Description | Status | Lead / Contact | Links |
|----------|-------------|--------|----------------|-------|
| `libsecp256k1` SP module | Cryptographic primitives for Silent Payments | ⚙️ In Progress | @josibake | [PR #1519](https://github.com/bitcoin-core/secp256k1/pull/1519) |
| Bitcoin Core (send/receive) | SP wallet support in Bitcoin Core | ⛔ Blocked (on above) | @josibake / @Eunovo | [Issue #28536](https://github.com/bitcoin/bitcoin/issues/28536) |

---

### Wallet Integrations

| Wallet | Send | Receive | Status | Lead / Contact | Notes |
|--------|------|---------|--------|----------------|-------|
| **Sparrow** | ✅ | ⚙️ | 🆘 Receiving WIP | ? | Needs indexer coordination |
| **BitBox02** | ✅ | ❌ | ✅ Partial | ShiftCrypto | Send-only |
| **Cake Wallet** | ✅ | ✅ (but slow) | ⚙️ | Cake Team | Needs indexing perf |
| **BlueWallet** | ✅ | ❌ | ✅ Partial | ? | Experimental branch |
| **Bitcoin Core** | ⚙️ | ⛔ | ⛔ | See above | Blocked on libsecp256k1 |

---

### Indexers & Servers

| Project | Description | Status | Lead | Links / Notes |
|---------|-------------|--------|------|----------------|
| **BlindBit Oracle** | Full-stack SP proof of concept | 🧪 | @yashraj (?) | Needs status update |
| **Electrs** | SP tweaks in Electrs | ⚙️ | @romanz| [PR 1075](https://github.com/romanz/electrs/pull/1075) |
| **Blockstream Esplora** | Heavy index, possible SP support | 🧪 | ? | [Cake fork](https://github.com/cake-tech/blockstream-electrs/tree/cake-update-v1) |
| **New SP Indexer** | Optimized tweak vending indexer | 🆘 | Open | Idea: filter for unspent only |
| **Outsourced Scanning Server** | Server does scanning for client | 🧪 | Open | UX tradeoff vs privacy |

---

### Protocol & Spec

| Topic | Description | Status | Lead / Contact | Notes |
|-------|-------------|--------|----------------|-------|
| **Light Client Protocol** | Fetch tweaks from server | 🧪 / 🆘 | @setavenger (?) | [Delving Discussion](https://delvingbitcoin.org/t/silent-payments-light-client-protocol/891) |
| **UX Guidelines** | Reusable address + Bolt12 design | 🆘 | [@yashrajd](https://github.com/yashrajd/) | [How it works: Silent payments](https://bitcoin.design/guide/how-it-works/silent-payments/) |
| **BIP-353** | Human-readable address format | ⚙️ | ? | Future enhancement |

---

## 📌 How to Contribute

→ Join the Discord (invite coming soon)
→ Start with an issue tagged `help wanted`

