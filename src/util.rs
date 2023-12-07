use std::io::Cursor;
use std::num::ParseIntError;

use base64::engine::general_purpose;
use base64::Engine;
use libflate::gzip::{Decoder, EncodeOptions, Encoder, HeaderBuilder};
use plist::{Error, Value};
use reqwest::{Certificate, Client};
use serde::{Deserialize, Serialize};
use std::fmt::Write as FmtWrite;
use std::io::{Read, Write};

pub fn make_reqwest() -> Client {
    let certificates = vec![
        Certificate::from_pem(include_bytes!(
            "../certs/root/albert.apple.com.digicert.cert"
        ))
        .unwrap(),
        Certificate::from_pem(include_bytes!(
            "../certs/root/profileidentity.ess.apple.com.cert"
        ))
        .unwrap(),
        Certificate::from_pem(include_bytes!(
            "../certs/root/init-p01st.push.apple.com.cert"
        ))
        .unwrap(),
        Certificate::from_pem(include_bytes!("../certs/root/init.ess.apple.com.cert")).unwrap(),
        Certificate::from_pem(include_bytes!("../certs/root/content-icloud-com.cert")).unwrap(),
    ];
    let mut builder = reqwest::Client::builder()
        .use_rustls_tls()
        .tls_built_in_root_certs(false);

    for certificate in certificates.into_iter() {
        builder = builder.add_root_certificate(certificate);
    }

    /*let builder = reqwest::Client::builder()
    .use_rustls_tls()
    .proxy(Proxy::https("https://localhost:8080").unwrap())
    .danger_accept_invalid_certs(true);*/

    builder.build().unwrap()
}

pub fn get_nested_value<'s>(val: &'s Value, path: &[&str]) -> Option<&'s Value> {
    let mut curr_val = val;
    for el in path {
        curr_val = curr_val.as_dictionary()?.get(el)?;
    }
    Some(curr_val)
}

// both in der
#[derive(Serialize, Deserialize, Clone)]
pub struct KeyPair {
    pub cert: Vec<u8>,
    pub private: Vec<u8>,
}

pub fn base64_encode(data: &[u8]) -> String {
    general_purpose::STANDARD.encode(data)
}
pub fn base64_decode(data: &str) -> Vec<u8> {
    general_purpose::STANDARD.decode(data.trim()).unwrap()
}

pub fn plist_to_string<T: serde::Serialize>(value: &T) -> Result<String, Error> {
    plist_to_buf(value).map(|val| String::from_utf8(val).unwrap())
}

pub fn plist_to_buf<T: serde::Serialize>(value: &T) -> Result<Vec<u8>, Error> {
    let mut buf: Vec<u8> = Vec::new();
    let writer = Cursor::new(&mut buf);
    plist::to_writer_xml(writer, &value)?;
    Ok(buf)
}

pub fn plist_to_bin<T: serde::Serialize>(value: &T) -> Result<Vec<u8>, Error> {
    let mut buf: Vec<u8> = Vec::new();
    let writer = Cursor::new(&mut buf);
    plist::to_writer_binary(writer, &value)?;
    Ok(buf)
}

pub fn gzip(bytes: &[u8]) -> Result<Vec<u8>, std::io::Error> {
    let header = HeaderBuilder::new().modification_time(0).finish();
    let options = EncodeOptions::new().header(header);
    let mut encoder = Encoder::with_options(Vec::new(), options)?;
    encoder.write_all(bytes)?;
    Ok(encoder.finish().into_result()?)
}

pub fn ungzip(bytes: &[u8]) -> Result<Vec<u8>, std::io::Error> {
    let mut decoder = Decoder::new(bytes)?;
    let mut decoded_data = Vec::new();
    decoder.read_to_end(&mut decoded_data)?;
    Ok(decoded_data)
}

pub fn decode_hex(s: &str) -> Result<Vec<u8>, ParseIntError> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16))
        .collect()
}

pub fn encode_hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        write!(&mut s, "{:02x}", b).unwrap();
    }
    s
}
