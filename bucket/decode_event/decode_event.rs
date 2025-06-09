// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
use std::collections::HashMap;
use std::sync::RwLock;
use std::error::Error;
use std::{fmt, error};
use serde::Deserialize;
use lens_sdk::StreamOption;
use lens_sdk::option::StreamOption::{Some, None, EndOfStream};
use sha3::{Digest, Keccak256};
use serde_json::Value;

#[link(wasm_import_module = "lens")]
extern "C" {
    fn next() -> *mut u8;
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Hash)]
enum ModuleError {
    ParametersNotSetError,
}

impl error::Error for ModuleError { }

impl fmt::Display for ModuleError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match &*self {
            ModuleError::ParametersNotSetError => f.write_str("Parameters have not been set."),
        }
    }
}

#[derive(Deserialize, Clone)]
pub struct Parameters {
    pub abi: String,
}

static PARAMETERS: RwLock<StreamOption<Parameters>> = RwLock::new(None);

#[no_mangle]
pub extern fn alloc(size: usize) -> *mut u8 {
    lens_sdk::alloc(size)
}

#[no_mangle]
pub extern fn set_param(ptr: *mut u8) -> *mut u8 {
    match try_set_param(ptr) {
        Ok(_) => lens_sdk::nil_ptr(),
        Err(e) => lens_sdk::to_mem(lens_sdk::ERROR_TYPE_ID, &e.to_string().as_bytes())
    }
}

fn try_set_param(ptr: *mut u8) -> Result<(), Box<dyn Error>> {
    let parameter = lens_sdk::try_from_mem::<Parameters>(ptr)?
        .ok_or(ModuleError::ParametersNotSetError)?;

    let mut dst = PARAMETERS.write()?;
    *dst = Some(parameter);
    Ok(())
}

#[no_mangle]
pub extern fn transform() -> *mut u8 {
    match try_transform() {
        Ok(o) => match o {
            Some(result_json) => lens_sdk::to_mem(lens_sdk::JSON_TYPE_ID, &result_json),
            None => lens_sdk::nil_ptr(),
            EndOfStream => lens_sdk::to_mem(lens_sdk::EOS_TYPE_ID, &[]),
        },
        Err(e) => lens_sdk::to_mem(lens_sdk::ERROR_TYPE_ID, &e.to_string().as_bytes())
    }
}

fn try_transform() -> Result<StreamOption<Vec<u8>>, Box<dyn Error>> {
    let ptr = unsafe { next() };
    let mut input = match lens_sdk::try_from_mem::<HashMap<String, serde_json::Value>>(ptr)? {
        Some(v) => v,
        // Implementations of `transform` are free to handle nil however they like. In this
        // implementation we chose to return nil given a nil input.
        None => return Ok(None),
        EndOfStream => return Ok(EndOfStream)
    };

    let tx_hash = input["transactionHash"]
        .as_str()
        .unwrap_or_default()
        .to_string();

    let block_number = input["blockNumber"]
        .as_i64()
        .unwrap_or_default()
        .to_string();

    // get all topics (the first is the sign, the rest are unindexed args)
    let topics: Vec<String> = input["topics"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap().to_string())
        .collect();

    // collect the first topic which is the signature like "Transfer(address,address,uint256)"
    let topic0 = &topics[0];

    // get the params, from here we can get the abi and parse it later
    let params = PARAMETERS.read()?
        .clone()
        .ok_or(ModuleError::ParametersNotSetError)?
        .clone();

    // parse the abi params into an array
    let parsed_abi: Vec<Value> = match serde_json::from_str(&params.abi) {
        Ok(v) => v,
        Err(e) => return Ok(None)
    };
    
    //loop through the array
    for item in parsed_abi.iter() {
        //  filter by event
        if item["type"] == "event" {
            let name = item["name"].as_str().unwrap();

            // extract types from inputs
            let empty: Vec<Value> = Vec::new();
            let inputs = item["inputs"].as_array().unwrap_or(&empty);

            // extract the types to be reused
            let types: Vec<&str> = inputs
                .iter()
                .map(|input| input["type"].as_str().unwrap())
                .collect();

            // build signature string
            let sig = format!("{}({})", name, types.join(","));

            // hash the signature
            let mut hasher = Keccak256::new();
            hasher.update(sig.as_bytes());
            let hashedsig = format!("0x{}", hex::encode(hasher.finalize()));

            // insert the tx hash and block number
            input.insert("hash".to_string(), serde_json::Value::String(tx_hash.clone()));
            input.insert("block".to_string(), serde_json::Value::String(block_number.clone()));

            // if hashedname is equals to topic0, we have found the event match now
            // now we can save the signature as the data and end the loop
            if hashedsig == *topic0 {
                // set the data to be the function
                input.insert("signature".to_string(), serde_json::Value::String(sig));

                // now take the rest of the topics and decode them using the inputs types

                // Decode the rest of the topics using the indexed input types
                let mut arguments = Vec::new();
                let mut indexed_items = Vec::new();

                // start from the second value because the first it the signature
                let mut topic_index = 1;

                for input_item in inputs.iter() {
                    let name = input_item["name"].as_str().unwrap_or_default();
                    let typ = input_item["type"].as_str().unwrap_or_default();

                    if input_item["indexed"].as_bool().unwrap_or(false) {
                        let topic = &topics[topic_index];

                        // decode this value
                        let value = decode_param(typ, topic);

                        arguments.push(serde_json::json!({
                            "name": name,
                            "type": typ,
                            "value": value.to_string()
                        }));
                    } else {
                        indexed_items.push(serde_json::json!({
                            "name": name,
                            "type": typ,
                        }));
                    }
                    topic_index += 1;
                }

                // get the data (with the data you get the remaining args)
                let data: String = input["data"].as_str().unwrap().to_string();

                // using the indexed_items array we can get the type and name to use to decode the index item
                // in the data var then add it to the arguments
                
                // Decode non-indexed values from the `data` hex string
                let data_bytes = hex::decode(data.strip_prefix("0x").unwrap_or(&data)).unwrap();
                let mut offset = 0;

                for input_item in indexed_items.iter() {
                    let name = input_item["name"].as_str().unwrap();
                    let typ = input_item["type"].as_str().unwrap();

                    let value = match typ {
                        "address" => {
                            // address is 20 bytes, right-aligned in 32 bytes
                            let start = offset + 12; // skip 12 bytes (24 hex chars) of padding
                            let end = offset + 32;
                            let addr = &data_bytes[start..end];
                            format!("0x{}", hex::encode(addr))
                        }
                        "uint256" => {
                            let start = offset;
                            let end = offset + 32;
                            let uint = &data_bytes[start..end];
                            format!("0x{}", hex::encode(uint))
                        }
                        "bool" => {
                            let b = data_bytes[offset + 31]; // last byte
                            (b != 0).to_string()
                        }
                        "bytes32" => {
                            let start = offset;
                            let end = offset + 32;
                            let bytes = &data_bytes[start..end];
                            format!("0x{}", hex::encode(bytes))
                        }
                        _ => {
                            format!("unsupported type: {}", typ)
                        }
                    };

                    // decode param before inserting
                    let val = decode_param(typ, &value);

                    arguments.push(serde_json::json!({
                        "name": name,
                        "type": typ,
                        "value": val,
                    }));

                    offset += 32;
                }

                input.insert("arguments".to_string(), serde_json::Value::Array(arguments));
                break;
            }
        }
    }

    // input.insert("data".to_string(), serde_json::Value::String(topic0.to_string()));

    let result_json = serde_json::to_vec(&input.clone())?;
    lens_sdk::free_transport_buffer(ptr)?;
    Ok(Some(result_json))
}

fn decode_param(typ: &str, hex_data: &str) -> String {
    let clean = hex_data.trim_start_matches("0x");

    match typ {
        "uint256" => {
            u128::from_str_radix(clean, 16)
                .map(|v| v.to_string())
                .unwrap_or_else(|_| "0".to_string())
        }
        "address" => {
            let addr = &clean[24..64]; // last 20 bytes (40 hex chars)
            format!("0x{}", addr)
        }
        "bool" => {
            let b = clean.ends_with("1");
            b.to_string()
        }
        "bytes32" => {
            format!("0x{}", clean)
        }
        _ => format!("unsupported type: {}", typ),
    }
}
