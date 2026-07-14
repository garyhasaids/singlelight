use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    Aes256Gcm, Key,
};
use base64::{engine::general_purpose, Engine as _};
use futures_util::StreamExt;
use serde::{Deserialize, Serialize};
use solana_client::{
    nonblocking::{pubsub_client::PubsubClient, rpc_client::RpcClient},
    rpc_config::{RpcTransactionLogsConfig, RpcTransactionLogsFilter},
};
use solana_sdk::{
    commitment_config::CommitmentConfig,
    pubkey::Pubkey,
    signature::{Keypair, Signer},
};
use sqlx::{sqlite::SqlitePoolOptions, Row, SqlitePool};
use std::{
    collections::HashMap,
    str::FromStr,
    sync::{Arc, OnceLock},
};
use teloxide::{
    dispatching::{
        dialogue,
        dialogue::{serializer::Json, SqliteStorage},
        UpdateFilterExt, UpdateHandler,
    },
    payloads::{SendMessageSetters, SendPhotoSetters},
    prelude::*,
    types::{InputFile, KeyboardButton, ParseMode, ReplyKeyboardMarkup},
};
use tokio::sync::Mutex;
use tokio::task::JoinHandle;

// ==========================================
// CONFIGURATION & TYPES
// ==========================================

/// Encryption key is loaded once at startup from the ENCRYPTION_KEY env var.
/// It is never hardcoded and never committed to source control.
static ENCRYPTION_KEY: OnceLock<[u8; 32]> = OnceLock::new();

/// Loads and validates ENCRYPTION_KEY from the environment. Panics with a clear
/// message on startup if it's missing or the wrong length, rather than silently
/// using an insecure default.
fn init_encryption_key() {
    let key_str = std::env::var("ENCRYPTION_KEY")
        .expect("ENCRYPTION_KEY env var must be set to a 32-byte secret before starting the bot");
    let bytes = key_str.as_bytes();
    assert_eq!(
        bytes.len(),
        32,
        "ENCRYPTION_KEY must be exactly 32 bytes, got {} bytes",
        bytes.len()
    );
    let mut key = [0u8; 32];
    key.copy_from_slice(bytes);
    ENCRYPTION_KEY
        .set(key)
        .expect("init_encryption_key called more than once");
}

fn encryption_key() -> &'static [u8; 32] {
    ENCRYPTION_KEY
        .get()
        .expect("encryption key accessed before init_encryption_key() was called")
}

/// RPC/WSS endpoints are configurable via env vars so they can be pointed at a
/// dedicated provider (Helius, QuickNode, etc.) instead of the public,
/// rate-limited mainnet endpoints.
fn rpc_url() -> String {
    std::env::var("SOLANA_RPC_URL").unwrap_or_else(|_| {
        log::warn!(
            "SOLANA_RPC_URL not set — falling back to the public mainnet RPC endpoint. \
             This is rate-limited and not recommended for production use."
        );
        "https://api.mainnet-beta.solana.com".to_string()
    })
}

fn wss_url() -> String {
    std::env::var("SOLANA_WSS_URL").unwrap_or_else(|_| {
        log::warn!(
            "SOLANA_WSS_URL not set — falling back to the public mainnet WSS endpoint. \
             This is rate-limited and not recommended for production use."
        );
        "wss://api.mainnet-beta.solana.com".to_string()
    })
}

type MyDialogue = Dialogue<State, SqliteStorage<Json>>;
type HandlerResult = Result<(), Box<dyn std::error::Error + Send + Sync>>;

/// Tracks the running copy-trade worker task per Telegram user, so a user
/// re-subscribing (or subscribing to a new wallet) cancels their previous
/// worker instead of leaking background tasks.
type WorkerRegistry = Arc<Mutex<HashMap<i64, JoinHandle<()>>>>;

#[derive(Clone, Default, Serialize, Deserialize)]
pub enum State {
    #[default]
    Idle,
    AwaitingBuyAddress,
    AwaitingCopyTradeWallet,
}

// ==========================================
// BLOCKCHAIN & CRYPTO ENGINE (Phases 2 & 3)
// ==========================================

/// Generates a new Solana keypair and returns (pubkey, encrypted_privkey_base64).
/// Returns an error instead of panicking on encryption failure.
pub fn generate_and_encrypt_wallet() -> Result<(String, String), String> {
    let keypair = Keypair::new();
    let pubkey = keypair.pubkey().to_string();
    let privkey = keypair.to_base58_string();

    let key = Key::<Aes256Gcm>::from_slice(encryption_key());
    let cipher = Aes256Gcm::new(key);
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);

    let ciphertext = cipher
        .encrypt(&nonce, privkey.as_bytes())
        .map_err(|e| format!("Encryption failed: {e}"))?;

    let mut encrypted_payload = nonce.to_vec();
    encrypted_payload.extend_from_slice(&ciphertext);
    let privkey_enc = general_purpose::STANDARD.encode(encrypted_payload);

    Ok((pubkey, privkey_enc))
}

/// Decrypts a base64-encoded, nonce-prefixed ciphertext back into the raw
/// base58 private key string. Returns an error instead of panicking on any
/// malformed input (bad base64, truncated payload, wrong key, etc.).
pub fn decrypt_wallet(encrypted_base64: &str) -> Result<String, String> {
    let encrypted_payload = general_purpose::STANDARD
        .decode(encrypted_base64)
        .map_err(|e| format!("Invalid base64 payload: {e}"))?;

    if encrypted_payload.len() < 12 {
        return Err("Encrypted payload is too short to contain a nonce".to_string());
    }
    let (nonce_bytes, ciphertext) = encrypted_payload.split_at(12);
    let nonce = aes_gcm::Nonce::from_slice(nonce_bytes);

    let key = Key::<Aes256Gcm>::from_slice(encryption_key());
    let cipher = Aes256Gcm::new(key);

    let decrypted_bytes = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|e| format!("Decryption failed: {e}"))?;

    String::from_utf8(decrypted_bytes).map_err(|e| format!("Invalid UTF-8 in private key: {e}"))
}

pub async fn get_sol_balance(pubkey_str: &str) -> Result<f64, Box<dyn std::error::Error + Send + Sync>> {
    let rpc_client = RpcClient::new(rpc_url());
    let pubkey = Pubkey::from_str(pubkey_str)?;
    let lamports = rpc_client.get_balance(&pubkey).await?;
    Ok(lamports as f64 / 1_000_000_000.0)
}

/// Runs the copy-trade log-subscription loop for a single target wallet.
/// Automatically reconnects with backoff if the WebSocket connection drops
/// or fails, instead of silently dying after the first disconnect.
async fn run_copy_trade_worker(target_wallet: String, _user_privkey_enc: String) {
    let mut backoff_secs: u64 = 1;
    const MAX_BACKOFF_SECS: u64 = 60;

    loop {
        log::info!("⚡ Connecting Copy Trade Listener for target: {}", target_wallet);

        let pubsub = match PubsubClient::new(&wss_url()).await {
            Ok(client) => client,
            Err(e) => {
                log::error!(
                    "WS connection failed for {}: {} — retrying in {}s",
                    target_wallet, e, backoff_secs
                );
                tokio::time::sleep(std::time::Duration::from_secs(backoff_secs)).await;
                backoff_secs = (backoff_secs * 2).min(MAX_BACKOFF_SECS);
                continue;
            }
        };

        let filter = RpcTransactionLogsFilter::Mentions(vec![target_wallet.clone()]);
        let config = RpcTransactionLogsConfig {
            commitment: Some(CommitmentConfig::confirmed()),
        };

        let (mut log_stream, _unsubscribe) = match pubsub.logs_subscribe(filter, config).await {
            Ok((stream, unsub)) => (stream, unsub),
            Err(e) => {
                log::error!(
                    "Failed to subscribe to logs for {}: {} — retrying in {}s",
                    target_wallet, e, backoff_secs
                );
                tokio::time::sleep(std::time::Duration::from_secs(backoff_secs)).await;
                backoff_secs = (backoff_secs * 2).min(MAX_BACKOFF_SECS);
                continue;
            }
        };

        log::info!("🎧 Listening for transactions on {}...", target_wallet);
        backoff_secs = 1; // reset backoff after a successful connection

        while let Some(log_response) = log_stream.next().await {
            let signature = log_response.value.signature;
            log::info!("🚨 New transaction detected! Signature: {}", signature);
            // TODO: Connect to Jupiter API to replicate the swap here
        }

        log::warn!(
            "Log stream for {} ended unexpectedly — reconnecting in {}s",
            target_wallet, backoff_secs
        );
        tokio::time::sleep(std::time::Duration::from_secs(backoff_secs)).await;
        backoff_secs = (backoff_secs * 2).min(MAX_BACKOFF_SECS);
    }
}

/// Spawns (or replaces) the copy-trade worker for a given Telegram user.
/// Aborts any previously running worker for that user first, so re-subscribing
/// doesn't leak background tasks or double-subscribe.
async fn spawn_copy_trade_worker(
    registry: &WorkerRegistry,
    telegram_id: i64,
    target_wallet: String,
    user_privkey_enc: String,
) {
    let mut guard = registry.lock().await;

    if let Some(old_handle) = guard.remove(&telegram_id) {
        old_handle.abort();
        log::info!("Aborted previous copy-trade worker for user {}", telegram_id);
    }

    let handle = tokio::spawn(run_copy_trade_worker(target_wallet, user_privkey_enc));
    guard.insert(telegram_id, handle);
}

// ==========================================
// TELEGRAM BOT LOGIC (Phase 1)
// ==========================================

#[tokio::main]
async fn main() {
    pretty_env_logger::init();
    init_encryption_key();
    log::info!("Starting Axiom trade bot...");

    // Setup SQLite File
    let db_path = "axiom_bot.db";
    if !std::path::Path::new(db_path).exists() {
        std::fs::File::create(db_path).expect("Failed to create database file");
    }

    // Initialize Connection Pool
    let db_url = format!("sqlite:{}", db_path);
    let db_pool = SqlitePoolOptions::new()
        .max_connections(5)
        .connect(&db_url)
        .await
        .expect("Failed to connect to SQLite");

    // Setup Main Table
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS users (
            telegram_id INTEGER PRIMARY KEY,
            sol_pubkey TEXT NOT NULL,
            sol_privkey_enc TEXT NOT NULL
        )",
    )
    .execute(&db_pool)
    .await
    .expect("Failed to create users table");

    // Setup Teloxide Dialogue Storage
    let storage = SqliteStorage::open(db_path, Json)
        .await
        .expect("Failed to initialize Teloxide dialogue storage");

    let worker_registry: WorkerRegistry = Arc::new(Mutex::new(HashMap::new()));

    let bot = Bot::from_env();

    Dispatcher::builder(bot, schema())
        .dependencies(dptree::deps![storage, db_pool, worker_registry])
        .enable_ctrlc_handler()
        .build()
        .dispatch()
        .await;
}

fn schema() -> UpdateHandler<Box<dyn std::error::Error + Send + Sync + 'static>> {
    use dptree::case;

    Update::filter_message()
        .enter_dialogue::<Message, SqliteStorage<Json>, State>()
        .branch(case![State::Idle].endpoint(handle_idle_state))
        .branch(case![State::AwaitingBuyAddress].endpoint(handle_buy_address))
        .branch(case![State::AwaitingCopyTradeWallet].endpoint(handle_copy_trade_wallet))
}

async fn handle_idle_state(
    bot: Bot,
    dialogue: MyDialogue,
    msg: Message,
    db_pool: SqlitePool,
) -> HandlerResult {
    if let Some(text) = msg.text() {
        match text {
            "/start" => {
                let telegram_id = msg.chat.id.0;

                // Atomic upsert: avoids a race where two rapid /start taps both
                // pass a SELECT check before either INSERT lands, which would
                // otherwise fail on the telegram_id primary key.
                let (new_pubkey, encrypted_privkey) = generate_and_encrypt_wallet()
                    .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { e.into() })?;

                sqlx::query(
                    "INSERT OR IGNORE INTO users (telegram_id, sol_pubkey, sol_privkey_enc) VALUES (?, ?, ?)",
                )
                .bind(telegram_id)
                .bind(&new_pubkey)
                .bind(&encrypted_privkey)
                .execute(&db_pool)
                .await?;

                // Re-select to get whichever row actually won the race
                // (either the one we just inserted, or an existing one).
                let row = sqlx::query("SELECT sol_pubkey FROM users WHERE telegram_id = ?")
                    .bind(telegram_id)
                    .fetch_one(&db_pool)
                    .await?;
                let pubkey: String = row.try_get("sol_pubkey")?;

                let balance = get_sol_balance(&pubkey).await.unwrap_or(0.0);
                send_welcome_menu(&bot, msg.chat.id, &pubkey, balance).await?;
            }
            "Buy 🚀" => {
                bot.send_message(msg.chat.id, "Please paste the token contract address to Buy:")
                    .await?;
                dialogue.update(State::AwaitingBuyAddress).await?;
            }
            "Copy Trade ⚡" => {
                bot.send_message(msg.chat.id, "Enter the wallet address you wish to copy trade:")
                    .await?;
                dialogue.update(State::AwaitingCopyTradeWallet).await?;
            }
            "Position 📈" => {
                bot.send_message(msg.chat.id, "Fetching your current open positions...")
                    .await?;
            }
            "Help" => {
                bot.send_message(msg.chat.id, "Axiom bot documentation and support...")
                    .await?;
            }
            _ => {
                bot.send_message(msg.chat.id, "Unrecognized command. Please use the menu buttons.")
                    .await?;
            }
        }
    }
    Ok(())
}

async fn handle_buy_address(bot: Bot, dialogue: MyDialogue, msg: Message) -> HandlerResult {
    match msg.text() {
        Some(token_address) => {
            let response = format!("✅ Executing buy order for contract: \n<code>{}</code>", token_address);
            bot.send_message(msg.chat.id, response).parse_mode(ParseMode::Html).await?;
            dialogue.exit().await?;
        }
        None => {
            bot.send_message(msg.chat.id, "Please send a valid text contract address.").await?;
        }
    }
    Ok(())
}

async fn handle_copy_trade_wallet(
    bot: Bot,
    dialogue: MyDialogue,
    msg: Message,
    db_pool: SqlitePool,
    worker_registry: WorkerRegistry,
) -> HandlerResult {
    match msg.text() {
        Some(target_wallet_address) => {
            let telegram_id = msg.chat.id.0;

            let row = sqlx::query("SELECT sol_privkey_enc FROM users WHERE telegram_id = ?")
                .bind(telegram_id)
                .fetch_optional(&db_pool)
                .await?;

            let sol_privkey_enc: String = match row {
                Some(r) => r.try_get("sol_privkey_enc")?,
                None => {
                    bot.send_message(msg.chat.id, "Please run /start first to create your wallet.")
                        .await?;
                    dialogue.exit().await?;
                    return Ok(());
                }
            };

            spawn_copy_trade_worker(
                &worker_registry,
                telegram_id,
                target_wallet_address.to_string(),
                sol_privkey_enc,
            )
            .await;

            let response = format!(
                "⚡ Successfully subscribed! Now copy trading wallet: \n<code>{}</code>\n\nYou will receive a notification when a swap executes.",
                target_wallet_address
            );
            bot.send_message(msg.chat.id, response).parse_mode(ParseMode::Html).await?;
            dialogue.exit().await?;
        }
        None => {
            bot.send_message(msg.chat.id, "Please send a valid text wallet address.").await?;
        }
    }
    Ok(())
}

async fn send_welcome_menu(bot: &Bot, chat_id: ChatId, pubkey: &str, balance: f64) -> HandlerResult {
    let keyboard = ReplyKeyboardMarkup::new(vec![
        vec![KeyboardButton::new("Buy 🚀"), KeyboardButton::new("Sell 🛠️")],
        vec![KeyboardButton::new("DCA orders")],
        vec![KeyboardButton::new("Position 📈"), KeyboardButton::new("My Trades 📊")],
        vec![KeyboardButton::new("Referrals 💰"), KeyboardButton::new("Copy Trade ⚡")],
        vec![KeyboardButton::new("Withdraw")],
        vec![KeyboardButton::new("Help"), KeyboardButton::new("Settings ⚙️")],
    ])
    .resize_keyboard(true)
    .is_persistent(true);

    let caption = format!(
        "<b>Welcome to Axiom trade bot!</b>\n\n\
                   Introducing a cutting-edge bot crafted exclusively for Solana Traders.\n\n\
                   <b>Balance:</b> {:.4} SOL\n\n\
                   Here's your Solana wallet address linked to your Telegram account. \
                   Simply fund your wallet to start trading.\n\n\
                   <code>{}</code>",
        balance, pubkey
    );

    // Note: Ensure you have an 'assets' folder with 'solana_logo.png' in your project root,
    // otherwise you can replace this block with standard `bot.send_message(...)`
    bot.send_photo(chat_id, InputFile::file("assets/solana_logo.png"))
        .caption(caption)
        .parse_mode(ParseMode::Html)
        .reply_markup(keyboard)
        .await?;

    Ok(())
}
