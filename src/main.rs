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
    signature::{Keypair, Signer}
};
use sqlx::{sqlite::SqlitePoolOptions, Row, SqlitePool};
use std::str::FromStr;
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

// ==========================================
// CONFIGURATION & TYPES
// ==========================================

/// ⚠️ PRODUCTION WARNING: Move to std::env::var("ENCRYPTION_KEY")
const ENCRYPTION_KEY: &[u8; 32] = b"axiom_trade_bot_secret_key_12345";
const RPC_URL: &str = "https://api.mainnet-beta.solana.com";
const WSS_URL: &str = "wss://api.mainnet-beta.solana.com";

type MyDialogue = Dialogue<State, SqliteStorage<Json>>;
type HandlerResult = Result<(), Box<dyn std::error::Error + Send + Sync>>;

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

pub fn generate_and_encrypt_wallet() -> (String, String) {
    let keypair = Keypair::new();
    let pubkey = keypair.pubkey().to_string();
    let privkey = keypair.to_base58_string();

    let key = Key::<Aes256Gcm>::from_slice(ENCRYPTION_KEY);
    let cipher = Aes256Gcm::new(key);
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);

    let ciphertext = cipher
        .encrypt(&nonce, privkey.as_bytes())
        .expect("Encryption failed");

    let mut encrypted_payload = nonce.to_vec();
    encrypted_payload.extend_from_slice(&ciphertext);
    let privkey_enc = general_purpose::STANDARD.encode(encrypted_payload);

    (pubkey, privkey_enc)
}

pub fn decrypt_wallet(encrypted_base64: &str) -> String {
    let encrypted_payload = general_purpose::STANDARD
        .decode(encrypted_base64)
        .expect("Invalid Base64 payload");

    let (nonce_bytes, ciphertext) = encrypted_payload.split_at(12);
    let nonce = aes_gcm::Nonce::from_slice(nonce_bytes);

    let key = Key::<Aes256Gcm>::from_slice(ENCRYPTION_KEY);
    let cipher = Aes256Gcm::new(key);

    let decrypted_bytes = cipher
        .decrypt(nonce, ciphertext)
        .expect("Decryption failed");

    String::from_utf8(decrypted_bytes).expect("Invalid UTF-8 in private key")
}

pub async fn get_sol_balance(pubkey_str: &str) -> Result<f64, Box<dyn std::error::Error + Send + Sync>> {
    let rpc_client = RpcClient::new(RPC_URL.to_string());
    let pubkey = Pubkey::from_str(pubkey_str)?;
    let lamports = rpc_client.get_balance(&pubkey).await?;
    Ok(lamports as f64 / 1_000_000_000.0)
}

pub async fn start_copy_trade_worker(target_wallet: String, _user_privkey_enc: String) {
    tokio::spawn(async move {
        log::info!("⚡ Starting Copy Trade Listener for target: {}", target_wallet);
        
        let pubsub = match PubsubClient::new(WSS_URL).await {
            Ok(client) => client,
            Err(e) => { log::error!("WS Connection Failed: {}", e); return; }
        };

        let filter = RpcTransactionLogsFilter::Mentions(vec![target_wallet.clone()]);
        let config = RpcTransactionLogsConfig { commitment: Some(CommitmentConfig::confirmed()) };

        let (mut log_stream, _unsubscribe) = match pubsub.logs_subscribe(filter, config).await {
            Ok((stream, unsub)) => (stream, unsub),
            Err(e) => { log::error!("Failed to subscribe to logs: {}", e); return; }
        };

        log::info!("🎧 Listening for transactions on {}...", target_wallet);

        while let Some(log_response) = log_stream.next().await {
            let signature = log_response.value.signature;
            log::info!("🚨 New transaction detected! Signature: {}", signature);
            // TODO: Connect to Jupiter API to replicate the swap here
        }
    });
}

// ==========================================
// TELEGRAM BOT LOGIC (Phase 1)
// ==========================================

#[tokio::main]
async fn main() {
    pretty_env_logger::init();
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
        )"
    )
    .execute(&db_pool)
    .await
    .expect("Failed to create users table");

    // Setup Teloxide Dialogue Storage
    let storage = SqliteStorage::open(db_path, Json)
        .await
        .expect("Failed to initialize Teloxide dialogue storage");

    let bot = Bot::from_env();

    Dispatcher::builder(bot, schema())
        .dependencies(dptree::deps![storage, db_pool])
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
                let user_row = sqlx::query("SELECT sol_pubkey FROM users WHERE telegram_id = ?")
                    .bind(msg.chat.id.0)
                    .fetch_optional(&db_pool)
                    .await?;

                let pubkey = match user_row {
                    Some(row) => row.try_get("sol_pubkey")?,
                    None => {
                        let (new_pubkey, encrypted_privkey) = generate_and_encrypt_wallet();
                        sqlx::query("INSERT INTO users (telegram_id, sol_pubkey, sol_privkey_enc) VALUES (?, ?, ?)")
                            .bind(msg.chat.id.0)
                            .bind(&new_pubkey)
                            .bind(&encrypted_privkey)
                            .execute(&db_pool)
                            .await?;
                        new_pubkey
                    }
                };

                let balance = get_sol_balance(&pubkey).await.unwrap_or(0.0);
                send_welcome_menu(&bot, msg.chat.id, &pubkey, balance).await?;
            }
            "Buy 🚀" => {
                bot.send_message(msg.chat.id, "Please paste the token contract address to Buy:").await?;
                dialogue.update(State::AwaitingBuyAddress).await?;
            }
            "Copy Trade ⚡" => {
                bot.send_message(msg.chat.id, "Enter the wallet address you wish to copy trade:").await?;
                dialogue.update(State::AwaitingCopyTradeWallet).await?;
            }
            "Position 📈" => {
                bot.send_message(msg.chat.id, "Fetching your current open positions...").await?;
            }
            "Help" => {
                bot.send_message(msg.chat.id, "Axiom bot documentation and support...").await?;
            }
            _ => {
                bot.send_message(msg.chat.id, "Unrecognized command. Please use the menu buttons.").await?;
            }
        }
    }
    Ok(())
}

async fn handle_buy_address(
    bot: Bot,
    dialogue: MyDialogue,
    msg: Message,
) -> HandlerResult {
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
) -> HandlerResult {
    match msg.text() {
        Some(target_wallet_address) => {
            let row = sqlx::query("SELECT sol_privkey_enc FROM users WHERE telegram_id = ?")
                .bind(msg.chat.id.0)
                .fetch_one(&db_pool)
                .await?;
            
            let sol_privkey_enc: String = row.try_get("sol_privkey_enc")?;

            start_copy_trade_worker(target_wallet_address.to_string(), sol_privkey_enc).await;

            let response = format!("⚡ Successfully subscribed! Now copy trading wallet: \n<code>{}</code>\n\nYou will receive a notification when a swap executes.", target_wallet_address);
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

    let caption = format!("<b>Welcome to Axiom trade bot!</b>\n\n\
                   Introducing a cutting-edge bot crafted exclusively for Solana Traders.\n\n\
                   <b>Balance:</b> {:.4} SOL\n\n\
                   Here's your Solana wallet address linked to your Telegram account. \
                   Simply fund your wallet to start trading.\n\n\
                   <code>{}</code>", balance, pubkey);

    // Note: Ensure you have an 'assets' folder with 'solana_logo.png' in your project root,
    // otherwise you can replace this block with standard `bot.send_message(...)`
    bot.send_photo(chat_id, InputFile::file("assets/solana_logo.png"))
        .caption(caption)
        .parse_mode(ParseMode::Html)
        .reply_markup(keyboard)
        .await?;

    Ok(())
}

