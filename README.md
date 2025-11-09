# 🛡️ Smart Contract Sentinel

**Smart Contract Sentinel** is a lightweight, Python-based blockchain security tool that detects potential **rug pulls, honeypots, and unsafe smart contracts** on **Ethereum** and **BNB Chain**.  
It combines static Solidity analysis with live on-chain verification and includes a **Telegram bot** for instant contract scanning.

---

## 🚀 Features
- 🔍 Detects risky Solidity patterns (`mint`, `blacklist`, `tx.origin`, etc.)
- 🌐 On-chain analysis via **Alchemy RPC** (ETH & BSC)
- ⚖️ Risk scoring (Low / Moderate / High)
- 🤖 Telegram bot for instant scans (`/scan <address> eth` or `/scan <address> bsc`)
- 💾 Auto-generates JSON reports under `/reports/`

---


