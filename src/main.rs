use std::{env, fmt::LowerHex};

use bitcoin_node_query::get_total_fee_for_block_at_height;
use bitcoind_request::{
    command::get_block::{CoinbaseVin, GetBlockCommand, GetBlockCommandVerbosity, NonCoinbaseVin},
    command::{get_block::GetBlockCommandResponse, CallableCommand},
    Blockhash,
};
use sha256::{digest, digest_bytes};

fn convert_decimal_to_hexadecimal(
    decimal_num: u64,
    include_prefix: bool,
    bytes: Option<u8>,
) -> String {
    let hex_string_without_prefix = match bytes {
        // two characters per byte
        Some(bytes) => match bytes {
            1 => format!("{:02x}", decimal_num),
            2 => format!("{:04x}", decimal_num),
            3 => format!("{:06x}", decimal_num),
            4 => format!("{:08x}", decimal_num),
            _ => panic!("bytes for hex not supported: {}", bytes),
        },
        None => format!("{:x}", decimal_num),
    };
    if include_prefix {
        format!("0x{hex_string_without_prefix}")
    } else {
        hex_string_without_prefix
    }
}
fn prefix_string(s: &str, prefix: &str) -> String {
    format!("{}{}", prefix, s)
}
fn add_hex_prefix(s: &String) -> String {
    prefix_string(s, "0x")
}

use std::{fmt::Write, num::ParseIntError};

pub fn decode_hex(s: &str) -> Result<Vec<u8>, ParseIntError> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16))
        .collect()
}

pub fn encode_hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        // We want to print the leading zero in each byte array item, so we need 02x formatting
        // here. So "0d" won't be printed as "d"
        write!(&mut s, "{:02x}", b).unwrap();
    }
    s
}

fn convert_big_endian_hex_to_little_endian(hex: &String) -> String {
    let decoded_hex = decode_hex(&hex).unwrap();
    let reversed_decoded_hex: Vec<u8> = decoded_hex.into_iter().rev().collect();
    let reversed_encoded_hex = encode_hex(&reversed_decoded_hex);
    reversed_encoded_hex
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

fn main() {
    let password = env::var("BITCOIND_PASSWORD").expect("BITCOIND_PASSWORD env variable not set");
    let username = env::var("BITCOIND_USERNAME").expect("BITCOIND_USERNAME env variable not set");
    let url = env::var("BITCOIND_URL").expect("BITCOIND_URL env variable not set");
    let bitcoind_request_client = bitcoind_request::client::Client::new(&url, &username, &password)
        .expect("failed to create client");
    let bitcoin_node_query_client = bitcoin_node_query::Client::new(&url, &username, &password)
        .expect("failed to create client");
    let get_block_command_response = GetBlockCommand::new(Blockhash(
        "0000000000000000000811d22829991146f1653a0c2d250e3b5999e7aa38eccd".to_string(),
    ))
    .verbosity(GetBlockCommandVerbosity::BlockObjectWithTransactionInformation)
    .call(&bitcoind_request_client);

    match get_block_command_response {
        GetBlockCommandResponse::Block(block) => {
            // TODO: DO NOT HARDCODE THIS. it should be in the bitcoin-node-query library
            let subsidy = 6.25;

            let fee_for_block_in_btc =
                get_total_fee_for_block_at_height(&bitcoin_node_query_client, block.height) as f64
                    / 100_000_000.0;
            let subsidy_plus_fees = subsidy + fee_for_block_in_btc;
            let version_hex_formatted =
                convert_decimal_to_hexadecimal(block.version, true, Some(4));
            let bits_hex_formatted = add_hex_prefix(&block.bits);
            let nonce_hex_formatted = convert_decimal_to_hexadecimal(block.nonce, true, None);

            let version_hex_string = convert_decimal_to_hexadecimal(block.version, false, None);
            let decoded_version_hex = decode_hex(&version_hex_string).unwrap();
            let reversed_decoded_version_hex: Vec<u8> =
                decoded_version_hex.into_iter().rev().collect();
            let prev_blockhash = block.previousblockhash.unwrap();

            let block_header_hex = construct_block_header_hex(
                BlockVersion::Int(block.version),
                &prev_blockhash,
                &block.merkleroot,
                block.time,
                &block.bits,
                block.nonce,
            );
            // let concatentated_le_hexes = construct_block_header(
            //     // &convert_decimal_to_hexadecimal(20000000, false, Some(4)),
            //     &"20000000".to_string(),
            //     &"00000000000000000003ecd827f336c6971f6f77a0b9fba362398dd867975645".to_string(),
            //     &"66b7c4a1926b41ceb2e617ddae0067e7bfea42db502017fde5b695a50384ed26".to_string(),
            //     &convert_decimal_to_hexadecimal(1571443461, false, None),
            //     &"1715a35c".to_string(),
            //     &"3f93ada7".to_string(),
            // );

            let block_hash = get_block_hash_from_block_header_hex(&block_header_hex);

            println!("height: {}", block.height);
            println!("hash: {}", block.hash);
            println!("prev hash: {:?}", &prev_blockhash);
            println!("time: {}", block.time);
            println!("size: {}", block.size);
            println!("weight: {}", block.weight);
            println!("median fee:");
            println!("total fees: {}", fee_for_block_in_btc,);
            println!("subsidy + fee: {}", subsidy_plus_fees);
            println!("miner: ");
            println!("---------------------");
            println!("version: {}", version_hex_formatted);
            println!("bits: {}", bits_hex_formatted);
            // println!("merkle root: {}", block.merkleroot);
            println!("difficulty: {}", block.difficulty);
            println!("nonce: {}", nonce_hex_formatted);
            println!("---------------------");
            //println!("prev hash: {:?}", block.previousblockhash);
            // println!("merkleroot: {}", block.merkleroot);
            println!("block header hex: {}", &block_header_hex);
            println!("---------------------");
            println!("transactions count: {}", block.tx.len());
            println!("--------------------------------TRANSACTIONS---------------------------------------------------------");
            let sub_transactions = &block.tx[1..6];
            for transaction in sub_transactions {
                match transaction {
                    bitcoind_request::command::get_block::GetBlockCommandTransactionResponse::Id(id) => {
                        todo!()
                    }
                    bitcoind_request::command::get_block::GetBlockCommandTransactionResponse::Raw(transaction) => {
                        if transaction.is_coinbase_transaction() {
                            println!("COINBASE TRANSACTION --------------------------------------------------------------------------------");
                        } else {
                            println!("TRANSACTION --------------------------------------------------------------------------------");
                        }
                        println!("txid: {}", transaction.txid);
                        println!("block time: {}", block.time);
                        println!("fees:");
                        println!("sat/vb: ");
                        println!("sat/vb: ");
                        println!("");
                        for vin in &transaction.vin {
                            println!("VIN ----------");
                            match vin {
                                bitcoind_request::command::get_block::Vin::Coinbase(cb_vin) => {
                                    println!("Coinbase: true");
                                    println!("sequence: {}", cb_vin.sequence);
                                },
                                bitcoind_request::command::get_block::Vin::NonCoinbase(non_cb_vin) => {
                                    println!("Coinbase: false");
                                    println!("from address: ");
                                    println!("from: from vout {} of transaction {}", non_cb_vin.vout, non_cb_vin.txid);
                                }
                            }
                            println!("--------------");
                            println!("");
                        }
                        for vout in &transaction.vout{
                            // TODO: don't use unwrap
                            let address = vout.script_pub_key.address.as_ref().unwrap();
                            let value = vout.value;
                            println!("Vout ----------");
                            println!("address: {}", address);
                            println!("value (sats): {}", value);
                            println!("--------------");
                        }
                        println!("--------------------------------------------------------------------------------------------");

                    }
                }
                println!("");
            }
            // println!("decoded version hex: {:#?}", decoded_version_hex);
            // println!(
            //     "decoded reversed version hex: {:#?}",
            //     reversed_encoded_version_hex
            // );
            // println!("median fee: {}", block.tx[0].);
        }
        GetBlockCommandResponse::BlockHash(hash) => panic!("not supported"),
    }
}
