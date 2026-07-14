Axiom Trade Bot
Axiom Trade Bot is a high-performance Telegram-based copy trading bot built specifically for the Solana blockchain. It provides an intuitive, menu-driven interface to execute swaps, track portfolios, and mirror the trading activity of target wallets in real-time.
The "Why"
Traditional decentralized trading is fragmented and slow. By leveraging Telegram’s interface and the speed of the Rust ecosystem, Axiom lowers the friction for users to participate in the fast-paced Solana ecosystem, allowing them to trade or copy-trade within seconds of a token launch.
Architecture
 * Framework: Teloxide (Telegram bot framework in Rust).
 * State Management: SQLite-backed Dialogues for persistent conversational flow.
 * Security: AES-256-GCM authenticated encryption for private key storage.
 * Blockchain: solana-client and solana-sdk for RPC interaction and wallet management.
What is Implemented
 * Conversational Engine: A robust state machine (Idle, AwaitingBuyAddress, etc.) that handles menu flow without losing context.
 * Persistent Storage: SQLite integration for both conversation states and user wallets.
 * Wallet Management:
   * Automatic Ed25519 keypair generation upon first /start.
   * Secure encryption/decryption of private keys using aes-gcm.
 * Live Blockchain Integration: * Real-time SOL balance fetching via mainnet RPC.
   * Background WebSocket workers that subscribe to logs of target wallets for copy-trading.
 * UI/UX: A persistent, custom ReplyKeyboardMarkup that mimics professional trading bot interfaces (e.g., Unibot/Trojan).
What is NOT Implemented
 * Swap Execution: While the listener detects transactions, the actual logic to call Jupiter/Raydium to replicate the swap is not yet active.
 * Referral System: The Referrals button is currently a placeholder.
 * Advanced Trading: DCA orders, custom gas/slippage settings, and portfolio profit/loss tracking (P&L) are not yet connected to the backend.
Roadmap: Next Steps
To get this from "foundation" to "production-ready," the following must be implemented:
1. The Swap Engine (Jupiter v6 API)
The most critical missing piece.
 * Requirement: Integrate the Jupiter Aggregator API.
 * Task: When a WebSocket log detects a swap, retrieve the transaction, ping /quote for the best route, and submit the trade via /swap using the decrypted user wallet.
2. Encryption Key Management
 * Requirement: Never hardcode secrets.
 * Task: Move ENCRYPTION_KEY to an environment variable and implement a secure key rotation policy.
3. Production RPC Infrastructure
 * Requirement: Reliability and Rate Limits.
 * Task: Swap the api.mainnet-beta.solana.com URL with a dedicated provider like Helius or QuickNode to ensure WebSocket stability during high market volatility.
4. Robust Error Handling
 * Task: Add explicit error handling for transaction failures, insufficient balance checks, and RPC timeout retries.
Getting Started
 * Clone the project.
 * Set your environment variable: export TELOXIDE_TOKEN="your_bot_token".
 * Ensure you have an assets/solana_logo.png file.
 * Build and Run: cargo run.
