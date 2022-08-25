use bitcoin_node_query::{get_total_fee_for_block_at_height, Client};

use bitcoind_request::{
    command::{
        get_block::{Block, DecodeRawTransactionResponse, GetBlockCommandResponse},
        get_block_hash::GetBlockHashCommand,
        get_raw_transaction::{Transaction, Vout},
        CallableCommand,
    },
    command::{
        get_block::{GetBlockCommand, GetBlockCommandVerbosity},
        get_raw_transaction::GetRawTransactionCommand,
    },
    Blockhash,
};
use chrono::{DateTime, Duration, NaiveDateTime, TimeZone, Utc};
use hex_utilities::{
    convert_big_endian_hex_to_little_endian, convert_decimal_to_hexadecimal, decode_hex,
    get_text_for_hex,
};
use std::env;

use sha256::digest_bytes;

fn pad_right(s: &str, pad: u64, padder: Option<&str>) -> String {
    match padder {
        Some(padder) => {
            let pad = padder.repeat(pad as usize);
            format!("{}{}", s, pad)
        }
        // This is much more performant as it doesn't allocated a new string
        None => format!("{:width$}", s, width = pad as usize + s.len()),
    }
}

fn pad_right_to_width(s: &str, width: u64, padder: Option<&str>) -> String {
    match padder {
        Some(padder) => {
            let pad = width - (s.len() as u64);
            pad_right(s, pad, Some(padder))
        }
        // This is much more performant as it doesn't allocated a new string
        None => format!("{:width$}", s, width = width as usize),
    }
}

fn row_componenent(field: &str, value: &str) -> String {
    let field_width = 20;
    let padder = ".";
    let formatted_field = format!("{}:", field);
    let padded_field = pad_right_to_width(&formatted_field, field_width, Some(padder));
    format!("{}{}", padded_field, value)
}
fn vin_row_component(address: String, value: String) -> String {
    let address_width = 60;
    let padder = ".";
    let formatted_address = format!("📥 {}", address);
    let padded_address = pad_right_to_width(&formatted_address, address_width, Some(padder));
    format!("{}{}", padded_address, value)
}
fn vout_row_component(address: String, value: String) -> String {
    let address_width = 60;
    let padder = ".";
    let formatted_address = format!("📤 {}:", address);
    let padded_address = pad_right_to_width(&formatted_address, address_width, Some(padder));
    format!("{}{}", padded_address, value)
}
fn op_return_vout_row_component(address: String, value: String) -> String {
    let address_width = 60;
    let padder = ".";
    let formatted_address = format!("📤 {}:", address);
    let padded_address = pad_right_to_width(&formatted_address, address_width, Some(padder));
    format!("{}{}", padded_address, value)
}
fn convert_bytes_to_kilobytes(byte_count: u64) -> f64 {
    byte_count as f64 / 1_000.0
}
fn convert_bytes_to_megabytes(byte_count: u64) -> f64 {
    let killobytes = convert_bytes_to_kilobytes(byte_count);
    killobytes / 1_000.0
}
fn convert_bytes_to_gigabytes(byte_count: u64) -> f64 {
    let megabytes = convert_bytes_to_megabytes(byte_count);
    megabytes / 1_000.0
}
fn convert_bytes_to_terabytes(byte_count: u64) -> f64 {
    let gigabytes = convert_bytes_to_gigabytes(byte_count);
    gigabytes / 1_000.0
}
fn convert_bytes_to_petabytes(byte_count: u64) -> f64 {
    let terabytes = convert_bytes_to_terabytes(byte_count);
    terabytes / 1_000.0
}

fn get_formatted_string_for_byte_count(byte_count: u64) -> String {
    let petabytes = convert_bytes_to_petabytes(byte_count);
    let terabytes = convert_bytes_to_terabytes(byte_count);
    let gigabytes = convert_bytes_to_gigabytes(byte_count);
    let megabytes = convert_bytes_to_megabytes(byte_count);
    let kilobytes = convert_bytes_to_kilobytes(byte_count);
    if petabytes > 1.0 {
        format!("{} pB", petabytes)
    } else if terabytes > 1.0 {
        format!("{} tB", terabytes)
    } else if gigabytes > 1.0 {
        format!("{} gB", gigabytes)
    } else if megabytes > 1.0 {
        format!("{} mB", megabytes)
    } else if kilobytes > 1.0 {
        format!("{} kB", kilobytes)
    } else {
        panic!("Shouldn't be reached")
    }
}

fn get_formatted_string_for_elapsed_seconds(seconds: i64) -> String {
    let time_since_datetime = Duration::seconds(seconds);
    let days_since_datetime = time_since_datetime.num_days();
    let hours_since_datetime = time_since_datetime.num_hours();
    let minutes_since_datetime = time_since_datetime.num_minutes();
    let seconds_since_datetime = time_since_datetime.num_seconds();
    let duration_formatted = if days_since_datetime > 0 {
        format!("{} days", days_since_datetime)
    } else if hours_since_datetime > 0 {
        format!("{} hours", hours_since_datetime)
    } else if minutes_since_datetime > 0 {
        format!("{} minutes", minutes_since_datetime)
    } else if seconds_since_datetime > 0 {
        format!("{} seconds", seconds_since_datetime)
    } else {
        panic!("DURATION NOT FOUND")
    };
    duration_formatted
}

fn get_timestamp_formatted(unix_timestamp: i64) -> String {
    let datetime = Utc.timestamp(unix_timestamp, 0);
    let now = Utc::now();
    let time_since_datetime = now - datetime;
    let seconds_since_datetime = time_since_datetime.num_seconds();
    let duration_formatted = get_formatted_string_for_elapsed_seconds(seconds_since_datetime);
    let datetime_formatted = datetime.format("%a, %b %e").to_string();
    format!("{} ({} ago)", datetime_formatted, duration_formatted)
}

fn get_op_returns_texts_for_asm(asm: String) -> Option<Vec<String>> {
    fn op_return_hexs_for_asm(asm: String) -> Option<Vec<String>> {
        let splits: Vec<String> = asm.split_whitespace().map(String::from).collect();
        let maybe_first = splits.first();
        let is_first_op_return = match maybe_first {
            Some(first) => first == &"OP_RETURN",
            None => false,
        };
        if is_first_op_return {
            let rest: Vec<String> = splits[0..].into_iter().map(String::from).collect();
            Some(rest)
        } else {
            None
        }
    }

    let maybe_op_return_hexes = op_return_hexs_for_asm(asm.to_string());
    match maybe_op_return_hexes {
        Some(op_return_hexes) => {
            let mut op_return_texts = vec![];
            for op_return_hex in op_return_hexes {
                let maybe_op_return_text = get_text_for_op_return_hex(&op_return_hex);
                match maybe_op_return_text {
                    Ok(op_return_text) => op_return_texts.push(op_return_text),
                    Err(_) => {}
                }
            }
            Some(op_return_texts)
        }
        None => None,
    }
}

fn get_text_for_op_return_hex(hex: &String) -> Result<String, hex_utilities::Error> {
    get_text_for_hex(hex)
}
fn strip_chars_that_take_up_extra_space(s: String) -> String {
    s.replace("\n", "")
        .replace("/t", "")
        .replace(|c: char| c == '\u{b}', "")
}
fn get_text_for_coinbase_sequence(hex: &String) -> Result<String, hex_utilities::Error> {
    get_text_for_hex(hex)
}

fn prefix_string(s: &str, prefix: &str) -> String {
    format!("{}{}", prefix, s)
}
fn add_hex_prefix(s: &String) -> String {
    prefix_string(s, "0x")
}

// The version for a block, from the bitcoin network, can be given as 1, 2, 0x00000002, 0x20000000, or in different values. If the version is given as decimal values like 1 or 2 it needs to be converted into a padded hexadecimal value first (0x00000002). If it is given as hex-value like this 0x20000000, it can be used as input value right away (it still needs to be converted to little-endian thought).
pub enum BlockVersion {
    Hex(String),
    Int(u64),
}

// Source: https://dlt-repo.net/how-to-calculate-a-bitcoin-block-hash-manually/
pub fn get_block_hash_from_block_header_hex(block_header_hex: &String) -> String {
    // To calculate the block hash:
    // convert block header hex into byte array
    let decoded = decode_hex(&block_header_hex).unwrap();
    // SHA256 hash the byte array
    let a = digest_bytes(&decoded);
    // convert the result of the 256 hash into a byte array
    let decoded_a = decode_hex(&a).unwrap();
    // SH256 hash the byte array
    let b = digest_bytes(&decoded_a);
    // convert the result of the second SHA25 hash into little endian.
    let block_hash = convert_big_endian_hex_to_little_endian(&b);
    block_hash
}

// Source: https://dlt-repo.net/how-to-calculate-a-bitcoin-block-hash-manually/
pub fn construct_block_header_hex(
    version: BlockVersion,
    previous_hash_hex: &String,
    merkleroot_hex: &String,
    timestamp: u64,
    bits_hex: &String,
    nonce: u64,
) -> String {
    // The version for a block, from the bitcoin network, can be given as 1, 2, 0x00000002, 0x20000000, or in different values. If the version is given as decimal values like 1 or 2 it needs to be converted into a padded hexadecimal value first (0x00000002). If it is given as hex-value like this 0x20000000, it can be used as input value right away (it still needs to be converted to little-endian thought).
    let version_hex = match version {
        BlockVersion::Hex(version_hex) => version_hex,
        BlockVersion::Int(version) => convert_decimal_to_hexadecimal(version, false, Some(4)),
    };
    let timestamp_hex = convert_decimal_to_hexadecimal(timestamp, false, None);
    let nonce_hex = convert_decimal_to_hexadecimal(nonce, false, None);

    let version_hex_le = convert_big_endian_hex_to_little_endian(&version_hex);
    let previous_hash_hex_le = convert_big_endian_hex_to_little_endian(previous_hash_hex);
    let merkleroot_hex_le = convert_big_endian_hex_to_little_endian(merkleroot_hex);
    let timestamp_hex_le = convert_big_endian_hex_to_little_endian(&timestamp_hex);

    let bits_hex_le = convert_big_endian_hex_to_little_endian(bits_hex);
    let nonce_hex_le = convert_big_endian_hex_to_little_endian(&nonce_hex);

    let concatentated_le_hexes = format!(
        "{}{}{}{}{}{}",
        version_hex_le,
        previous_hash_hex_le,
        merkleroot_hex_le,
        timestamp_hex_le,
        bits_hex_le,
        nonce_hex_le
    );
    concatentated_le_hexes
}
fn print_transaction(
    transaction: &Transaction,
    bitcoind_request_client: &bitcoind_request::client::Client,
    should_show_vout_detils_of_vin: bool,
) {
    println!("");
    if transaction.is_coinbase_transaction() {
        println!("====== ✨ COINBASE TRANSACTION ✨ ============================================");
    } else {
        println!("====== TRANSACTION ============================================");
    }
    println!("{}", row_componenent("txid", &transaction.txid));
    println!(
        "{}",
        row_componenent(
            "block time",
            &get_timestamp_formatted(transaction.time as i64)
        )
    );
    println!("{}", row_componenent("fees", &"TBD sats".to_string()));
    println!("{}", row_componenent("fee rate", &"TBD sat/vB".to_string()));
    println!("---------- vins --------------------------------------------------");
    for vin in &transaction.vin {
        match vin {
            bitcoind_request::command::get_raw_transaction::Vin::Coinbase(cb_vin) => {
                println!(" Coinbase (New Coins)");
                let coinbase = &cb_vin.coinbase;
                let maybe_text_for_coinbase_sequence = get_text_for_coinbase_sequence(coinbase);
                match maybe_text_for_coinbase_sequence {
                    Ok(text_for_coinbase) => {
                        println!(
                            "{}",
                            strip_chars_that_take_up_extra_space(text_for_coinbase)
                        );
                    }
                    Err(_) => {}
                }
            }
            bitcoind_request::command::get_raw_transaction::Vin::NonCoinbase(non_cb_vin) => {
                let txid = non_cb_vin.txid.clone();
                let get_raw_transaction_command_response = GetRawTransactionCommand::new(txid)
                    .verbose(true)
                    .call(&bitcoind_request_client)
                    .unwrap();
                let vout_num = non_cb_vin.vout;
                let maybe_vout_for_vin = 
                        match get_raw_transaction_command_response {
                            bitcoind_request::command::get_raw_transaction::GetRawTransactionCommandResponse::SerializedHexEncodedData(_hex) => {todo!()},
                            bitcoind_request::command::get_raw_transaction::GetRawTransactionCommandResponse::Transaction(transaction) => {
                            let mut maybe_vout_for_vin: Option<Vout> = None;
                                for vout in transaction.vout {
                                    if vout.n == vout_num {
                                        maybe_vout_for_vin = Some(vout);
                                    }
                                }
                                maybe_vout_for_vin
                            },
                        };

                let asm = &non_cb_vin.script_sig.asm;
                let maybe_opt_returns = get_op_returns_texts_for_asm(asm.to_string());
                match maybe_opt_returns {
                    Some(opt_returns) => {
                        for opt_return in opt_returns {
                            println!(
                                "OP_RETURN: {}",
                                strip_chars_that_take_up_extra_space(opt_return)
                            );
                        }
                    }
                    None => {}
                }
                let vout_for_vin = maybe_vout_for_vin.unwrap();
                let maybe_vout_for_vin_address = &vout_for_vin
                                .script_pub_key
                                .address;
                let address_text = match maybe_vout_for_vin_address {
                    Some(vout_for_vin_address) => vout_for_vin_address,
                    None => "N/A"
                };
                println!(
                    "{}",
                    vin_row_component(
                        format!(
                            "{}",
                            address_text
                        ),
                        format!("{} BTC", &vout_for_vin.value).to_string()
                    )
                    .to_string()
                );
                if should_show_vout_detils_of_vin {
                    println!("+++++++ DETAILS on vin and vout ++++++++++");
                    println!("{:#?}", &vout_for_vin);
                    println!("{:#?}", vin);
                    println!("+++++++ END DEAILS ++++++++++");
                }
            }
        }
    }
    println!("---------- vouts --------------------------------------------------");
    for vout in &transaction.vout {
        // print!("{:#?}", vout);
        // TODO: don't use unwrap
        // println!("Vout: {:#?}", vout);
        let maybe_address = vout.script_pub_key.address.as_ref();
        let asm = &vout.script_pub_key.asm;
        let maybe_opt_returns = get_op_returns_texts_for_asm(asm.to_string());
        let value = vout.value;
        match maybe_opt_returns {
            Some(opt_returns) => {
                for opt_return in opt_returns {
                    println!(
                        "{}",
                        op_return_vout_row_component(
                            format!("OP_RETURN ({} BTC)", value).to_string(),
                            format!("{}", strip_chars_that_take_up_extra_space(opt_return)),
                        )
                        .to_string()
                    );
                }
            }
            None => {
                println!(
                    "{}",
                    vout_row_component(
                        format!(
                            "{}",
                            maybe_address.unwrap_or(&"N/A".to_string()).to_string()
                        ),
                        format!("{} BTC", value).to_string(),
                    )
                    .to_string()
                )
            }
        }
    }
    println!("===============================================================");
    println!("");
}
fn print_transaction_for_block(
    transaction: &DecodeRawTransactionResponse,
    block_time: u64,
    bitcoind_request_client: &bitcoind_request::client::Client,
) {
    println!("");
    if transaction.is_coinbase_transaction() {
        println!("====== ✨ COINBASE TRANSACTION ✨ ============================================");
    } else {
        println!("====== TRANSACTION ============================================");
    }
    println!("{}", row_componenent("txid", &transaction.txid));
    println!("{}", row_componenent("block time", &block_time.to_string()));
    println!("{}", row_componenent("fees", &"TBD sats".to_string()));
    println!("{}", row_componenent("fee rate", &"TBD sat/vB".to_string()));
    println!("---------- vins --------------------------------------------------");
    for vin in &transaction.vin {
        match vin {
            bitcoind_request::command::get_block::Vin::Coinbase(cb_vin) => {
                println!(" Coinbase (New Coins)");
                let coinbase = &cb_vin.coinbase;
                let maybe_text_for_coinbase_sequence = get_text_for_coinbase_sequence(coinbase);
                match maybe_text_for_coinbase_sequence {
                    Ok(text_for_coinbase) => {
                        println!(
                            "{}",
                            strip_chars_that_take_up_extra_space(text_for_coinbase)
                        );
                    }
                    Err(_) => {}
                }
            }
            bitcoind_request::command::get_block::Vin::NonCoinbase(non_cb_vin) => {
                let txid = non_cb_vin.txid.clone();
                let get_raw_transaction_command_response = GetRawTransactionCommand::new(txid)
                    .verbose(true)
                    .call(&bitcoind_request_client)
                    .unwrap();
                let vout_num = non_cb_vin.vout;
                let (address, value) = match get_raw_transaction_command_response {
                                            bitcoind_request::command::get_raw_transaction::GetRawTransactionCommandResponse::SerializedHexEncodedData(_hex) => {todo!()},
                                            bitcoind_request::command::get_raw_transaction::GetRawTransactionCommandResponse::Transaction(transaction) => {
                                                let mut address: Option<String> = None;
                                                let mut value: Option<f64> = None;
                                                for vout in transaction.vout {
                                                    if vout.n == vout_num {
                                                        address = vout.script_pub_key.address;
                                                        value = Some(vout.value)
                                                    }
                                                }
                                                (address, value)
                                            },
                                        };
                let asm = &non_cb_vin.script_sig.asm;
                let maybe_opt_returns = get_op_returns_texts_for_asm(asm.to_string());
                match maybe_opt_returns {
                    Some(opt_returns) => {
                        for opt_return in opt_returns {
                            println!(
                                "OP_RETURN: {}",
                                strip_chars_that_take_up_extra_space(opt_return)
                            );
                        }
                    }
                    None => {}
                }
                println!(
                    "{}",
                    vin_row_component(
                        format!("{}", address.unwrap_or("N/A".to_string()).to_string()),
                        format!("{} BTC", value.unwrap()).to_string()
                    )
                    .to_string()
                )
            }
        }
    }
    println!("---------- vouts --------------------------------------------------");
    for vout in &transaction.vout {
        // TODO: don't use unwrap
        // println!("Vout: {:#?}", vout);
        let maybe_address = vout.script_pub_key.address.as_ref();
        let asm = &vout.script_pub_key.asm;
        let maybe_opt_returns = get_op_returns_texts_for_asm(asm.to_string());
        let value = vout.value;
        match maybe_opt_returns {
            Some(opt_returns) => {
                for opt_return in opt_returns {
                    println!(
                        "{}",
                        op_return_vout_row_component(
                            format!("OP_RETURN ({} BTC)", value).to_string(),
                            format!("{}", strip_chars_that_take_up_extra_space(opt_return)),
                        )
                        .to_string()
                    );
                }
            }
            None => {
                println!(
                    "{}",
                    vout_row_component(
                        format!(
                            "{}",
                            maybe_address.unwrap_or(&"N/A".to_string()).to_string()
                        ),
                        format!("{} BTC", value).to_string(),
                    )
                    .to_string()
                )
            }
        }
    }
    println!("===============================================================");
    println!("");
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let first_arg = &args[1];
    let maybe_second_arg = &args.get(2);
    let is_verbose_indicated = maybe_second_arg.is_some();
    let password = env::var("BITCOIND_PASSWORD").expect("BITCOIND_PASSWORD env variable not set");
    let username = env::var("BITCOIND_USERNAME").expect("BITCOIND_USERNAME env variable not set");
    let url = env::var("BITCOIND_URL").expect("BITCOIND_URL env variable not set");
    let bitcoind_request_client = bitcoind_request::client::Client::new(&url, &username, &password)
        .expect("failed to create client");
    let bitcoin_node_query_client = bitcoin_node_query::Client::new(&url, &username, &password)
        .expect("failed to create client");

    let maybe_block_hash: Option<String> = match first_arg.parse::<u64>() {
        Ok(height) => {
            let maybe_get_block_hash_command_response =
                GetBlockHashCommand::new(height).call(&bitcoind_request_client);
            match maybe_get_block_hash_command_response {
                Ok(get_block_hash_command_response) => {
                    Some(get_block_hash_command_response.0 .0.to_string())
                }
                Err(err) => None,
            }
        }
        Err(error) => None,
    };
    // let get_block_command_response = GetBlockCommand::new(Blockhash(
    //     "00000000000000000008fc4136a664f78ac1a648a6c28ef1733dd07c88cbd0ae".to_string(),
    // ));
    match maybe_block_hash {
        Some(block_hash) => {
            let get_block_command_response =
                GetBlockCommand::new(Blockhash(block_hash.to_string()))
                    .verbosity(GetBlockCommandVerbosity::BlockObjectWithTransactionInformation)
                    .call(&bitcoind_request_client)
                    .unwrap();
            match get_block_command_response {
                GetBlockCommandResponse::Block(block) => {
                    print_block(block, bitcoin_node_query_client, bitcoind_request_client)
                }
                GetBlockCommandResponse::BlockHash(_hash) => panic!("not supported"),
            }
        }
        None => {
            let get_raw_transaction_command_response_result = GetRawTransactionCommand::new(
                "5ea35103fba386dec1027e176a14f8c9004d0410f5dfc3c485148332aee01375".to_string(),
            )
            .verbose(true)
            .call(&bitcoind_request_client);
            let transaction = match get_raw_transaction_command_response_result {
                Ok(get_raw_transaction_command_response) => {
                    match get_raw_transaction_command_response {
                        bitcoind_request::command::get_raw_transaction::GetRawTransactionCommandResponse::SerializedHexEncodedData(_hex) => {todo!()},
                        bitcoind_request::command::get_raw_transaction::GetRawTransactionCommandResponse::Transaction(transaction) => {
                            transaction
                        }
                    }
                },
                Err(error) => {
                    todo!()
                }
            };
            // Don't hardcode blocktime
            print_transaction(&transaction, &bitcoind_request_client, is_verbose_indicated)
        }
    }
}

fn print_block(
    block: Block,
    bitcoin_node_query_client: Client,
    bitcoind_request_client: bitcoind_request::client::Client,
) {
    // TODO: DO NOT HARDCODE THIS. it should be in the bitcoin-node-query library
    let subsidy = 6.25;

    let fee_for_block_in_btc =
        get_total_fee_for_block_at_height(&bitcoin_node_query_client, block.height) as f64
            / 100_000_000.0;
    let subsidy_plus_fees = subsidy + fee_for_block_in_btc;
    let version_hex_formatted = convert_decimal_to_hexadecimal(block.version, true, Some(4));
    let bits_hex_formatted = add_hex_prefix(&block.bits);
    let nonce_hex_formatted = convert_decimal_to_hexadecimal(block.nonce, true, None);

    let prev_blockhash = block.previousblockhash.unwrap();

    let block_header_hex = construct_block_header_hex(
        BlockVersion::Int(block.version),
        &prev_blockhash,
        &block.merkleroot,
        block.time,
        &block.bits,
        block.nonce,
    );

    println!("");
    println!("");
    println!(
                "******** BLOCK: {} ********************************************************************************************************************************************************************",
                block.height
            );
    println!("{}", row_componenent("Height", &block.height.to_string()));
    println!("{}", row_componenent("Hash", &block.hash));
    println!("{}", row_componenent("Prev Hash", &prev_blockhash));
    println!(
        "{}",
        row_componenent("Time", &get_timestamp_formatted(block.time as i64))
    );
    println!(
        "{}",
        row_componenent("Size", &get_formatted_string_for_byte_count(block.size))
    );
    println!("{}", row_componenent("Weight", &block.weight.to_string()));
    println!("{}", row_componenent("Median Fee", "TDB"));
    println!(
        "{}",
        row_componenent("Total Fees", &fee_for_block_in_btc.to_string())
    );
    println!(
        "{}",
        row_componenent("Subsidy + Fee", &subsidy_plus_fees.to_string())
    );
    println!("------------------------------------------------------");
    println!("{}", row_componenent("Version", &version_hex_formatted));
    println!("{}", row_componenent("Bits", &bits_hex_formatted));
    println!("{}", row_componenent("Merkle root", &block.merkleroot));
    println!(
        "{}",
        row_componenent("Difficulty", &block.difficulty.to_string())
    );
    println!("{}", row_componenent("Nonce", &nonce_hex_formatted));
    println!("{}", row_componenent("Block Header Hex", &block_header_hex));
    println!(
        "{}",
        row_componenent("Transactions", &block.tx.len().to_string())
    );
    println!("--------------------------------TRANSACTIONS---------------------------------------------------------");
    // let sub_transactions = &block.tx[1..6];
    // let transactions = sub_transactions
    let transactions = block.tx;
    // TODO: VERY Inefficient. We're looping over all the transactions twice, when we
    // should only be doing it once.
    let mut transactions_not_including_coinbase: Vec<DecodeRawTransactionResponse> = vec![];
    let mut coinbase_transaction: Option<DecodeRawTransactionResponse> = None;
    for transaction in transactions {
        match transaction {
            bitcoind_request::command::get_block::GetBlockCommandTransactionResponse::Id(id) => {
                todo!()
            }
            bitcoind_request::command::get_block::GetBlockCommandTransactionResponse::Raw(
                transaction,
            ) => {
                if transaction.is_coinbase_transaction() {
                    coinbase_transaction = Some(transaction);
                } else {
                    transactions_not_including_coinbase.push(transaction);
                }
            }
        }
    }
    // println!("coinbase: {:?}", &coinbase_transaction.unwrap());
    match coinbase_transaction {
        Some(cb_transaction) => {
            print_transaction_for_block(&cb_transaction, block.time, &bitcoind_request_client);
        }
        None => {
            todo!()
        }
    }
    // print_transaction(&transaction, block.time, &bitcoind_request_client);
    // for transaction in &transactions_not_including_coinbase[0..5] {
    //     print_transaction_for_block(&transaction, block.time, &bitcoind_request_client);
    // }
}
