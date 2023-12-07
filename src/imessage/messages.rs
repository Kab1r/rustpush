use std::{
    fmt,
    io::{Cursor, Read, Write},
    time::{SystemTime, UNIX_EPOCH},
    vec,
};

use async_trait::async_trait;
use log::{debug, warn};
use openssl::symm::{Cipher, Crypter};
use plist::Data;
use rand::Rng;
use regex::Regex;
use uuid::Uuid;
use xml::{reader, writer::XmlEvent, EmitterConfig, EventReader};

use crate::{
    apns::APNSConnection,
    error::PushError,
    mmcs::{get_mmcs, prepare_put, put_mmcs, Container, DataCacher, PreparedPut},
    mmcsp,
    util::{decode_hex, encode_hex, gzip, plist_to_bin, ungzip},
};

include!("./rawmessages.rs");

const ZERO_NONCE: [u8; 16] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];

#[repr(C)]
pub struct BalloonBody {
    pub bid: String,
    pub data: Vec<u8>,
}

// conversation data, used to uniquely identify a conversation from a message
#[repr(C)]
pub struct ConversationData {
    pub participants: Vec<String>,
    pub cv_name: Option<String>,
    pub sender_guid: Option<String>,
}

#[repr(C)]
pub enum MessagePart {
    Text(String),
    Attachment(Attachment),
}

#[repr(C)]
pub struct IndexedMessagePart(pub MessagePart, pub Option<usize>);

#[repr(C)]
pub struct MessageParts(pub Vec<IndexedMessagePart>);

impl MessageParts {
    fn has_attachments(&self) -> bool {
        self.0
            .iter()
            .any(|p| matches!(p.0, MessagePart::Attachment(_)))
    }

    fn from_raw(raw: &str) -> MessageParts {
        MessageParts(vec![IndexedMessagePart(
            MessagePart::Text(raw.to_string()),
            None,
        )])
    }

    // Convert parts into xml for a RawIMessage
    fn to_xml(&self, mut raw: Option<&mut RawIMessage>) -> String {
        let mut output = vec![];
        let mut writer_config = EmitterConfig::new().write_document_declaration(false);
        writer_config.perform_escaping = false;
        let mut writer = writer_config.create_writer(Cursor::new(&mut output));
        writer.write(XmlEvent::start_element("html")).unwrap();
        writer.write(XmlEvent::start_element("body")).unwrap();
        let mut inline_attachment_num = 0;
        for (idx, part) in self.0.iter().enumerate() {
            let part_idx = part.1.unwrap_or(idx).to_string();
            match &part.0 {
                MessagePart::Attachment(attachment) => {
                    let filesize = attachment.get_size().to_string();
                    let element = XmlEvent::start_element("FILE")
                        .attr("name", &attachment.name)
                        .attr("width", "0")
                        .attr("height", "0")
                        .attr("datasize", &filesize)
                        .attr("mime-type", &attachment.mime)
                        .attr("uti-type", &attachment.uti_type)
                        .attr("file-size", &filesize)
                        .attr("message-part", &part_idx);
                    match &attachment.a_type {
                        AttachmentType::Inline(data) => {
                            let num = if inline_attachment_num == 0 {
                                if let Some(raw) = &mut raw {
                                    raw.inline0 = Some(data.clone().into());
                                }
                                "ia-0"
                            } else if inline_attachment_num == 1 {
                                if let Some(raw) = &mut raw {
                                    raw.inline1 = Some(data.clone().into());
                                }
                                "ia-1"
                            } else {
                                continue;
                            };
                            writer
                                .write(element.attr("inline-attachment", num))
                                .unwrap();

                            inline_attachment_num += 1;
                        }
                        AttachmentType::MMCS(mmcs) => {
                            writer
                                .write(
                                    element
                                        .attr("mmcs-signature-hex", &encode_hex(&mmcs.signature))
                                        .attr("mmcs-url", &mmcs.url)
                                        .attr("mmcs-owner", &mmcs.object)
                                        .attr(
                                            "decryption-key",
                                            &encode_hex(&[vec![0x00], mmcs.key.clone()].concat()),
                                        ),
                                )
                                .unwrap();
                        }
                    }
                }
                MessagePart::Text(text) => {
                    writer
                        .write(XmlEvent::start_element("span").attr("message-part", &part_idx))
                        .unwrap();
                    writer
                        .write(XmlEvent::Characters(
                            html_escape::encode_text(&text).as_ref(),
                        ))
                        .unwrap();
                }
            }
            writer.write(XmlEvent::end_element()).unwrap();
        }
        writer.write(XmlEvent::end_element()).unwrap();
        writer.write(XmlEvent::end_element()).unwrap();
        let msg = std::str::from_utf8(&output).unwrap().to_string();
        debug!("xml body {}", msg);
        msg
    }

    // parse XML parts
    fn parse_parts(xml: &str, raw: Option<&RawIMessage>) -> MessageParts {
        let mut data: Vec<IndexedMessagePart> = vec![];
        let reader: EventReader<Cursor<&str>> = EventReader::new(Cursor::new(xml));
        let mut string_buf = String::new();
        let mut text_part_idx: Option<usize> = None;
        for e in reader {
            match e {
                Ok(reader::XmlEvent::StartElement {
                    name,
                    attributes,
                    namespace: _,
                }) => {
                    let get_attr = |name: &str, def: Option<&str>| {
                        attributes
                            .iter()
                            .find(|attr| attr.name.to_string() == name)
                            .map_or_else(
                                || {
                                    def.expect(&format!("attribute {} doesn't exist!", name))
                                        .to_string()
                                },
                                |data| data.value.to_string(),
                            )
                    };
                    let part_idx = attributes
                        .iter()
                        .find(|attr| attr.name.to_string() == "message-part")
                        .map(|opt| opt.value.parse().unwrap());
                    if name.local_name == "FILE" {
                        if string_buf.trim().len() > 0 {
                            data.push(IndexedMessagePart(
                                MessagePart::Text(string_buf),
                                text_part_idx,
                            ));
                            string_buf = String::new();
                            text_part_idx = None;
                        }
                        data.push(IndexedMessagePart(
                            MessagePart::Attachment(Attachment {
                                a_type: if let Some(inline) = attributes
                                    .iter()
                                    .find(|attr| attr.name.to_string() == "inline-attachment")
                                {
                                    AttachmentType::Inline(if inline.value == "ia-0" {
                                        raw.map_or(vec![], |raw| {
                                            raw.inline0.clone().unwrap().into()
                                        })
                                    } else if inline.value == "ia-1" {
                                        raw.map_or(vec![], |raw| {
                                            raw.inline1.clone().unwrap().into()
                                        })
                                    } else {
                                        continue;
                                    })
                                } else {
                                    let sig =
                                        decode_hex(&get_attr("mmcs-signature-hex", None)).unwrap();
                                    let key =
                                        decode_hex(&get_attr("decryption-key", None)).unwrap();
                                    AttachmentType::MMCS(MMCSFile {
                                        signature: sig.clone(), // chop off first byte because it's not actually the signature
                                        object: get_attr("mmcs-owner", None),
                                        url: get_attr("mmcs-url", None),
                                        key: key[1..].to_vec(),
                                        size: get_attr("file-size", None).parse().unwrap(),
                                    })
                                },
                                part: attributes
                                    .iter()
                                    .find(|attr| attr.name.to_string() == "message-part")
                                    .map(|item| item.value.parse().unwrap())
                                    .unwrap_or(0),
                                uti_type: get_attr("uti-type", None),
                                mime: get_attr("mime-type", Some("application/octet-stream")),
                                name: get_attr("name", None),
                                iris: get_attr("iris", Some("no")) == "yes",
                            }),
                            part_idx,
                        ))
                    } else if name.local_name == "span" {
                        text_part_idx = part_idx;
                    }
                }
                Ok(reader::XmlEvent::Characters(data)) => {
                    string_buf += &data;
                }
                _ => {}
            }
        }
        if string_buf.trim().len() > 0 {
            data.push(IndexedMessagePart(
                MessagePart::Text(string_buf),
                text_part_idx,
            ));
        }
        MessageParts(data)
    }

    pub fn raw_text(&self) -> String {
        self.0
            .iter()
            .filter_map(|m| match &m.0 {
                MessagePart::Text(text) => Some(text.clone()),
                MessagePart::Attachment(_) => None,
            })
            .collect::<Vec<String>>()
            .join("\n")
    }
}

// a "normal" imessage, containing multiple parts and text
#[repr(C)]
pub struct NormalMessage {
    pub parts: MessageParts,
    pub body: Option<BalloonBody>,
    pub effect: Option<String>,
    pub reply_guid: Option<String>,
    pub reply_part: Option<String>,
}

impl NormalMessage {
    pub fn new(text: String) -> NormalMessage {
        NormalMessage {
            parts: MessageParts(vec![IndexedMessagePart(MessagePart::Text(text), None)]),
            body: None,
            effect: None,
            reply_guid: None,
            reply_part: None,
        }
    }
}

#[repr(C)]
pub struct RenameMessage {
    pub new_name: String,
}

#[repr(C)]
pub struct ChangeParticipantMessage {
    pub new_participants: Vec<String>,
    pub group_version: u64,
}

#[repr(C)]
pub enum Reaction {
    Heart,
    Like,
    Dislike,
    Laugh,
    Emphsize,
    Question,
}

#[repr(C)]
pub struct ReactMessage {
    pub to_uuid: String,
    pub to_part: u64,
    pub enable: bool,
    pub reaction: Reaction,
    pub to_text: String,
}

impl ReactMessage {
    fn get_text(&self) -> String {
        if self.enable {
            format!(
                "{} “{}”",
                match self.reaction {
                    Reaction::Heart => "Loved",
                    Reaction::Like => "Liked",
                    Reaction::Dislike => "Disliked",
                    Reaction::Laugh => "Laughed at",
                    Reaction::Emphsize => "Emphasized",
                    Reaction::Question => "Questioned",
                },
                self.to_text
            )
        } else {
            format!(
                "Removed a{} from “{}”",
                match self.reaction {
                    Reaction::Heart => " heart",
                    Reaction::Like => " like",
                    Reaction::Dislike => " dislike",
                    Reaction::Laugh => " laugh",
                    Reaction::Emphsize => "n exclamation",
                    Reaction::Question => " question mark",
                },
                self.to_text
            )
        }
    }
    fn get_idx(&self) -> u64 {
        match self.reaction {
            Reaction::Heart => 0,
            Reaction::Like => 1,
            Reaction::Dislike => 2,
            Reaction::Laugh => 3,
            Reaction::Emphsize => 4,
            Reaction::Question => 5,
        }
    }

    fn from_idx(idx: u64) -> Option<Reaction> {
        Some(match idx {
            0 => Reaction::Heart,
            1 => Reaction::Like,
            2 => Reaction::Dislike,
            3 => Reaction::Laugh,
            4 => Reaction::Emphsize,
            5 => Reaction::Question,
            _ => return None,
        })
    }
}

#[repr(C)]
pub struct UnsendMessage {
    pub tuuid: String,
    pub edit_part: u64,
}

#[repr(C)]
pub struct EditMessage {
    pub tuuid: String,
    pub edit_part: u64,
    pub new_parts: MessageParts,
}

pub struct IMessageContainer<'a> {
    crypter: Crypter,
    writer: Option<&'a mut (dyn Write + Send + Sync)>,
    reader: Option<&'a mut (dyn Read + Send + Sync)>,
    cacher: DataCacher,
    finalized: bool,
}

impl IMessageContainer<'_> {
    fn new<'a>(
        key: &[u8],
        writer: Option<&'a mut (dyn Write + Send + Sync)>,
        reader: Option<&'a mut (dyn Read + Send + Sync)>,
    ) -> IMessageContainer<'a> {
        IMessageContainer {
            crypter: Crypter::new(
                Cipher::aes_256_ctr(),
                if writer.is_some() {
                    openssl::symm::Mode::Decrypt
                } else {
                    openssl::symm::Mode::Encrypt
                },
                key,
                Some(&ZERO_NONCE),
            )
            .unwrap(),
            writer,
            reader,
            cacher: DataCacher::new(),
            finalized: false,
        }
    }

    fn finish(&mut self) -> Vec<u8> {
        if self.finalized {
            return vec![];
        }
        self.finalized = true;
        let block_size = Cipher::aes_256_ctr().block_size();
        let mut extra = vec![0; block_size];
        let len = self.crypter.finalize(&mut extra).unwrap();
        extra.resize(len, 0);
        extra
    }
}

#[async_trait]
impl<'a> Container for IMessageContainer<'a> {
    async fn finalize(&mut self) -> Result<Option<mmcsp::confirm_response::Request>, PushError> {
        let extra = self.finish();
        if let Some(writer) = &mut self.writer {
            writer.write(&extra)?;
        }
        Ok(None)
    }
    async fn read(&mut self, len: usize) -> Result<Vec<u8>, PushError> {
        let mut recieved = self.cacher.read_exact(len);
        while recieved.is_none() {
            let mut data = vec![0; len];
            let read = self.reader.as_mut().unwrap().read(&mut data)?;
            if read == 0 {
                let ciphertext = self.finish();
                self.cacher.data_avail(&ciphertext);
                recieved = self
                    .cacher
                    .read_exact(len)
                    .or_else(|| Some(self.cacher.read_all()));
                break;
            } else {
                data.resize(read, 0);
                let block_size = Cipher::aes_256_ctr().block_size();
                let mut ciphertext = vec![0; data.len() + block_size];
                let len = self.crypter.update(&data, &mut ciphertext).unwrap();
                ciphertext.resize(len, 0);
                self.cacher.data_avail(&ciphertext);
            }
            recieved = self.cacher.read_exact(len);
        }

        Ok(recieved.unwrap_or(vec![]))
    }
    async fn write(&mut self, data: &[u8]) -> Result<(), PushError> {
        let block_size = Cipher::aes_256_ctr().block_size();
        let mut plaintext = vec![0; data.len() + block_size];
        let len = self.crypter.update(&data, &mut plaintext).unwrap();
        plaintext.resize(len, 0);
        self.writer.as_mut().unwrap().write(&plaintext)?;
        Ok(())
    }

    fn get_progress_count(&self) -> usize {
        0 // we are not the transfer
    }
}

pub struct AttachmentPreparedPut {
    mmcs: PreparedPut,
    key: [u8; 32],
}

#[repr(C)]
#[derive(Clone)]
pub struct MMCSFile {
    signature: Vec<u8>,
    object: String,
    url: String,
    key: Vec<u8>,
    size: usize,
}

impl From<MMCSTransferData> for MMCSFile {
    fn from(value: MMCSTransferData) -> Self {
        MMCSFile {
            signature: decode_hex(&value.mmcs_signature_hex).unwrap(),
            object: value.mmcs_owner,
            url: value.mmcs_url,
            key: decode_hex(&value.decryption_key).unwrap()[1..].to_vec(),
            size: value.file_size.parse().unwrap(),
        }
    }
}

impl Into<MMCSTransferData> for MMCSFile {
    fn into(self) -> MMCSTransferData {
        MMCSTransferData {
            mmcs_signature_hex: encode_hex(&self.signature).to_uppercase(),
            mmcs_owner: self.object,
            mmcs_url: self.url,
            decryption_key: encode_hex(&[vec![0x0], self.key].concat()),
            file_size: self.size.to_string(),
        }
    }
}

impl MMCSFile {
    pub async fn prepare_put(
        reader: &mut (dyn Read + Send + Sync),
    ) -> Result<AttachmentPreparedPut, PushError> {
        let key = rand::thread_rng().gen::<[u8; 32]>();
        let mut send_container = IMessageContainer::new(&key, None, Some(reader));
        let prepared = prepare_put(&mut send_container).await?;
        Ok(AttachmentPreparedPut {
            mmcs: prepared,
            key,
        })
    }

    // create and upload a new attachment to MMCS
    pub async fn new(
        apns: &APNSConnection,
        prepared: &AttachmentPreparedPut,
        reader: &mut (dyn Read + Send + Sync),
        progress: &mut dyn FnMut(usize, usize),
    ) -> Result<MMCSFile, PushError> {
        let mut send_container = IMessageContainer::new(&prepared.key, None, Some(reader));
        let result = put_mmcs(&mut send_container, &prepared.mmcs, apns, progress).await?;

        let url = format!("{}/{}", result.0, result.1);

        Ok(MMCSFile {
            signature: prepared.mmcs.total_sig.to_vec(),
            object: result.1,
            url,
            key: prepared.key.to_vec(),
            size: prepared.mmcs.total_len,
        })
    }

    // request to get and download attachment from MMCS
    pub async fn get_attachment(
        &self,
        apns: &APNSConnection,
        writer: &mut (dyn Write + Send + Sync),
        progress: &mut dyn FnMut(usize, usize),
    ) -> Result<(), PushError> {
        let mut recieve_container = IMessageContainer::new(&self.key, Some(writer), None);
        get_mmcs(
            &self.signature,
            &self.url,
            &self.object,
            apns,
            &mut recieve_container,
            progress,
        )
        .await?;

        Ok(())
    }
}

#[repr(C)]
pub enum AttachmentType {
    Inline(Vec<u8>),
    MMCS(MMCSFile),
}

#[repr(C)]

pub struct Attachment {
    a_type: AttachmentType,
    part: u64,
    uti_type: String,
    mime: String,
    name: String,
    iris: bool, // or live photo
}

impl Attachment {
    pub async fn new_mmcs(
        apns: &APNSConnection,
        prepared: &AttachmentPreparedPut,
        reader: &mut (dyn Read + Send + Sync),
        mime: &str,
        uti: &str,
        name: &str,
        progress: &mut dyn FnMut(usize, usize),
    ) -> Result<Attachment, PushError> {
        let mmcs = MMCSFile::new(apns, prepared, reader, progress).await?;
        Ok(Attachment {
            a_type: AttachmentType::MMCS(mmcs),
            part: 0,
            uti_type: uti.to_string(),
            mime: mime.to_string(),
            name: name.to_string(),
            iris: false,
        })
    }

    pub fn get_size(&self) -> usize {
        match &self.a_type {
            AttachmentType::Inline(data) => data.len(),
            AttachmentType::MMCS(mmcs) => mmcs.size,
        }
    }

    pub async fn get_attachment(
        &self,
        apns: &APNSConnection,
        writer: &mut (dyn Write + Send + Sync),
        progress: &mut dyn FnMut(usize, usize),
    ) -> Result<(), PushError> {
        match &self.a_type {
            AttachmentType::Inline(data) => {
                writer.write_all(&data.clone())?;
                Ok(())
            }
            AttachmentType::MMCS(mmcs) => mmcs.get_attachment(apns, writer, progress).await,
        }
    }
}

// file should be 570x570 png
#[repr(C)]
pub struct IconChangeMessage {
    pub file: Option<MMCSFile>,
    pub group_version: u64,
}

#[repr(C)]
pub enum Message {
    Message(NormalMessage),
    RenameMessage(RenameMessage),
    ChangeParticipants(ChangeParticipantMessage),
    React(ReactMessage),
    Delivered,
    Read,
    Typing,
    Unsend(UnsendMessage),
    Edit(EditMessage),
    IconChange(IconChangeMessage),
    StopTyping,
}

impl Message {
    // also add new C values to client.rs raw_inbound
    pub(super) fn get_c(&self) -> u8 {
        match self {
            Self::Message(_) => 100,
            Self::React(_) => 100,
            Self::RenameMessage(_) => 190,
            Self::ChangeParticipants(_) => 190,
            Self::Delivered => 101,
            Self::Read => 102,
            Self::Typing => 100,
            Self::Edit(_) => 118,
            Self::Unsend(_) => 118,
            Self::IconChange(_) => 190,
            Self::StopTyping => 100,
        }
    }

    pub(super) fn get_nr(&self) -> Option<bool> {
        match self {
            Self::Typing => Some(true),
            Self::Delivered => Some(true),
            Self::Edit(_) => Some(true),
            Self::Unsend(_) => Some(true),
            _ => None,
        }
    }
}

impl fmt::Display for Message {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Message::Message(msg) => {
                write!(f, "{}", msg.parts.raw_text())
            }
            Message::RenameMessage(msg) => {
                write!(f, "renamed the chat to {}", msg.new_name)
            }
            Message::ChangeParticipants(msg) => {
                write!(f, "changed participants {:?}", msg.new_participants)
            }
            Message::React(msg) => {
                write!(f, "{}", msg.get_text())
            }
            Message::Read => {
                write!(f, "read")
            }
            Message::Delivered => {
                write!(f, "delivered")
            }
            Message::Typing => {
                write!(f, "typing")
            }
            Message::Edit(e) => {
                write!(f, "Edited {}", e.new_parts.raw_text())
            }
            Message::Unsend(_e) => {
                write!(f, "unsent a message")
            }
            Message::IconChange(_e) => {
                write!(f, "changed the group icon")
            }
            Message::StopTyping => {
                write!(f, "stopped typing")
            }
        }
    }
}

fn remove_prefix(participants: &[String]) -> Vec<String> {
    participants
        .iter()
        .map(|p| p.replace("mailto:", "").replace("tel:", ""))
        .collect()
}

fn add_prefix(participants: &[String]) -> Vec<String> {
    participants
        .clone()
        .iter()
        .map(|p| {
            if p.contains("@") {
                format!("mailto:{}", p)
            } else {
                format!("tel:{}", p)
            }
        })
        .collect()
}

// a message that can be sent to other iMessage users
#[repr(C)]
pub struct IMessage {
    pub id: String,
    pub sender: Option<String>,
    pub after_guid: Option<String>,
    pub conversation: Option<ConversationData>,
    pub message: Message,
    pub sent_timestamp: u64,
}

impl IMessage {
    pub(super) fn sanity_check_send(&mut self) {
        let conversation = self.conversation.as_mut().expect("no convo for send!??!?");
        if conversation.sender_guid.is_none() {
            conversation.sender_guid = Some(Uuid::new_v4().to_string());
        }
        if !conversation
            .participants
            .contains(self.sender.as_ref().unwrap())
        {
            conversation
                .participants
                .push(self.sender.as_ref().unwrap().clone());
        }
    }

    pub fn has_payload(&self) -> bool {
        match &self.message {
            Message::Read => false,
            Message::Delivered => false,
            Message::Typing => false,
            _ => true,
        }
    }

    pub fn get_ex(&self) -> Option<u32> {
        match &self.message {
            Message::Typing => Some(0),
            Message::StopTyping => Some(0),
            _ => None,
        }
    }

    pub(super) fn to_raw(&mut self) -> Vec<u8> {
        let mut should_gzip = false;
        let conversation = self.conversation.as_ref().unwrap();
        let binary = match &self.message {
            Message::RenameMessage(msg) => {
                let raw = RawRenameMessage {
                    participants: remove_prefix(&conversation.participants),
                    sender_guid: conversation.sender_guid.clone(),
                    gv: "8".to_string(),
                    new_name: msg.new_name.clone(),
                    old_name: conversation.cv_name.clone(),
                    name: msg.new_name.clone(),
                    msg_type: "n".to_string(),
                };
                plist_to_bin(&raw).unwrap()
            }
            Message::StopTyping => {
                let raw = RawIMessage {
                    text: None,
                    xml: None,
                    participants: conversation.participants.clone(),
                    after_guid: None,
                    sender_guid: conversation.sender_guid.clone(),
                    pv: 0,
                    gv: "8".to_string(),
                    v: "1".to_string(),
                    bid: None,
                    b: None,
                    effect: None,
                    cv_name: conversation.cv_name.clone(),
                    reply: None,
                    inline0: None,
                    inline1: None,
                    live_xml: None,
                };

                plist_to_bin(&raw).unwrap()
            }
            Message::ChangeParticipants(msg) => {
                let raw = RawChangeMessage {
                    target_participants: remove_prefix(&msg.new_participants),
                    source_participants: remove_prefix(&conversation.participants),
                    sender_guid: conversation.sender_guid.clone(),
                    gv: "8".to_string(),
                    new_name: conversation.cv_name.clone().unwrap(),
                    name: conversation.cv_name.clone().unwrap(),
                    msg_type: "p".to_string(),
                    group_version: msg.group_version,
                };
                plist_to_bin(&raw).unwrap()
            }
            Message::React(react) => {
                let amt = if react.enable {
                    react.get_idx() + 2000
                } else {
                    react.get_idx() + 3000
                };
                let text = react.get_text();
                let raw = RawReactMessage {
                    text: text,
                    amrln: react.to_text.len() as u64,
                    amrlc: 0,
                    amt: amt,
                    participants: conversation.participants.clone(),
                    after_guid: self.after_guid.clone(),
                    sender_guid: conversation.sender_guid.clone(),
                    pv: 0,
                    gv: "8".to_string(),
                    v: "1".to_string(),
                    cv_name: conversation.cv_name.clone(),
                    msi: plist_to_bin(&MsiData {
                        ams: "test".to_string(),
                        amc: 1,
                    })
                    .unwrap()
                    .into(),
                    amk: format!("p:{}/{}", react.to_part, react.to_uuid),
                };
                plist_to_bin(&raw).unwrap()
            }
            Message::Message(normal) => {
                let mut raw = RawIMessage {
                    text: Some(normal.parts.raw_text()),
                    xml: None,
                    participants: conversation.participants.clone(),
                    after_guid: self.after_guid.clone(),
                    sender_guid: conversation.sender_guid.clone(),
                    pv: 0,
                    gv: "8".to_string(),
                    v: "1".to_string(),
                    bid: None,
                    b: None,
                    effect: normal.effect.clone(),
                    cv_name: conversation.cv_name.clone(),
                    reply: normal
                        .reply_guid
                        .as_ref()
                        .map(|guid| format!("r:{}:{}", normal.reply_part.as_ref().unwrap(), guid)),
                    inline0: None,
                    inline1: None,
                    live_xml: None,
                };

                if normal.parts.has_attachments() {
                    raw.xml = Some(normal.parts.to_xml(Some(&mut raw)));
                }

                should_gzip = !raw.xml.is_some();

                plist_to_bin(&raw).unwrap()
            }
            Message::Delivered => panic!("no enc body!"),
            Message::Read => panic!("no enc body!"),
            Message::Typing => panic!("no enc body!"),
            Message::Unsend(msg) => {
                let raw = RawUnsendMessage {
                    rs: true,
                    message: msg.tuuid.clone(),
                    et: 2,
                    part_index: msg.edit_part,
                    v: "1".to_string(),
                };
                plist_to_bin(&raw).unwrap()
            }
            Message::Edit(msg) => {
                let raw = RawEditMessage {
                    new_html_body: msg.new_parts.to_xml(None),
                    et: 1,
                    part_index: msg.edit_part,
                    message: msg.tuuid.clone(),
                    new_text: msg.new_parts.raw_text(),
                };

                plist_to_bin(&raw).unwrap()
            }
            Message::IconChange(msg) => {
                let start = SystemTime::now();
                let since_the_epoch = start
                    .duration_since(UNIX_EPOCH)
                    .expect("Time went backwards");
                let random_guid = Uuid::new_v4().to_string().to_uppercase();
                let raw = RawIconChangeMessage {
                    group_version: msg.group_version,
                    new_icon: msg.file.as_ref().map(|file| IMTransferData {
                        created_date: (since_the_epoch.as_nanos() as f64) / 1000000000f64,
                        filename_key: "GroupPhotoImage".to_string(),
                        local_user_info: file.clone().into(),
                        transfer_guid: format!("at_0_{}", random_guid),
                        message_guid: random_guid.clone(),
                    }),
                    sender_guid: conversation.sender_guid.clone(),
                    msg_type: "v".to_string(),
                    participants: remove_prefix(&conversation.participants),
                    gv: "8".to_string(),
                    cv_name: conversation.cv_name.clone(),
                };

                warn!(
                    "sent {:?}",
                    plist::Value::from_reader(Cursor::new(&plist_to_bin(&raw).unwrap()))
                );

                plist_to_bin(&raw).unwrap()
            }
        };
        debug!(
            "sending: {:?}",
            plist::Value::from_reader(Cursor::new(&binary))
        );

        // do not gzip xml
        let final_msg = if !should_gzip {
            binary
        } else {
            gzip(&binary).unwrap()
        };

        final_msg
    }

    pub(super) fn from_raw(bytes: &[u8], wrapper: &RecvMsg) -> Option<IMessage> {
        let decompressed = ungzip(&bytes).unwrap_or_else(|_| bytes.to_vec());
        debug!(
            "xml: {:?}",
            plist::Value::from_reader(Cursor::new(&decompressed))
        );
        if let Ok(loaded) = plist::from_bytes::<RawUnsendMessage>(&decompressed) {
            let msg_guid: Vec<u8> = wrapper.msg_guid.clone().into();
            return Some(IMessage {
                sender: Some(wrapper.sender.clone()),
                id: Uuid::from_bytes(msg_guid.try_into().unwrap())
                    .to_string()
                    .to_uppercase(),
                after_guid: None,
                sent_timestamp: wrapper.sent_timestamp / 1000000,
                conversation: None,
                message: Message::Unsend(UnsendMessage {
                    tuuid: loaded.message,
                    edit_part: loaded.part_index,
                }),
            });
        }
        if let Ok(loaded) = plist::from_bytes::<RawEditMessage>(&decompressed) {
            let msg_guid: Vec<u8> = wrapper.msg_guid.clone().into();
            return Some(IMessage {
                sender: Some(wrapper.sender.clone()),
                id: Uuid::from_bytes(msg_guid.try_into().unwrap())
                    .to_string()
                    .to_uppercase(),
                after_guid: None,
                sent_timestamp: wrapper.sent_timestamp / 1000000,
                conversation: None,
                message: Message::Edit(EditMessage {
                    tuuid: loaded.message,
                    edit_part: loaded.part_index,
                    new_parts: MessageParts::parse_parts(&loaded.new_html_body, None),
                }),
            });
        }
        if let Ok(loaded) = plist::from_bytes::<RawChangeMessage>(&decompressed) {
            let msg_guid: Vec<u8> = wrapper.msg_guid.clone().into();
            return Some(IMessage {
                sender: Some(wrapper.sender.clone()),
                id: Uuid::from_bytes(msg_guid.try_into().unwrap())
                    .to_string()
                    .to_uppercase(),
                after_guid: None,
                sent_timestamp: wrapper.sent_timestamp / 1000000,
                conversation: Some(ConversationData {
                    participants: add_prefix(&loaded.source_participants),
                    cv_name: Some(loaded.name.clone()),
                    sender_guid: loaded.sender_guid.clone(),
                }),
                message: Message::ChangeParticipants(ChangeParticipantMessage {
                    new_participants: add_prefix(&loaded.target_participants),
                    group_version: loaded.group_version,
                }),
            });
        }
        if let Ok(loaded) = plist::from_bytes::<RawIconChangeMessage>(&decompressed) {
            warn!(
                "recieved {:?}",
                plist::Value::from_reader(Cursor::new(&decompressed))
            );
            let msg_guid: Vec<u8> = wrapper.msg_guid.clone().into();
            return Some(IMessage {
                sender: Some(wrapper.sender.clone()),
                id: Uuid::from_bytes(msg_guid.try_into().unwrap())
                    .to_string()
                    .to_uppercase(),
                after_guid: None,
                sent_timestamp: wrapper.sent_timestamp / 1000000,
                conversation: Some(ConversationData {
                    participants: add_prefix(&loaded.participants),
                    cv_name: loaded.cv_name.clone(),
                    sender_guid: loaded.sender_guid.clone(),
                }),
                message: Message::IconChange(IconChangeMessage {
                    file: loaded.new_icon.map(|icon| icon.local_user_info.into()),
                    group_version: loaded.group_version,
                }),
            });
        }
        if let Ok(loaded) = plist::from_bytes::<RawRenameMessage>(&decompressed) {
            let msg_guid: Vec<u8> = wrapper.msg_guid.clone().into();
            return Some(IMessage {
                sender: Some(wrapper.sender.clone()),
                id: Uuid::from_bytes(msg_guid.try_into().unwrap())
                    .to_string()
                    .to_uppercase(),
                after_guid: None,
                sent_timestamp: wrapper.sent_timestamp / 1000000,
                conversation: Some(ConversationData {
                    participants: add_prefix(&loaded.participants),
                    cv_name: loaded.old_name.clone(),
                    sender_guid: loaded.sender_guid.clone(),
                }),
                message: Message::RenameMessage(RenameMessage {
                    new_name: loaded.new_name.clone(),
                }),
            });
        }
        if let Ok(loaded) = plist::from_bytes::<RawReactMessage>(&decompressed) {
            let msg_guid: Vec<u8> = wrapper.msg_guid.clone().into();
            let target_msg_data = Regex::new(r"p:([0-9]+)/([0-9A-F\-]+)")
                .unwrap()
                .captures(&loaded.amk)
                .unwrap();
            let enabled = loaded.amt < 3000;
            let id = if enabled {
                loaded.amt - 2000
            } else {
                loaded.amt - 3000
            };
            return Some(IMessage {
                sender: Some(wrapper.sender.clone()),
                id: Uuid::from_bytes(msg_guid.try_into().unwrap())
                    .to_string()
                    .to_uppercase(),
                after_guid: loaded.after_guid.clone(),
                sent_timestamp: wrapper.sent_timestamp / 1000000,
                conversation: Some(ConversationData {
                    participants: loaded.participants.clone(),
                    cv_name: loaded.cv_name.clone(),
                    sender_guid: loaded.sender_guid.clone(),
                }),
                message: Message::React(ReactMessage {
                    to_uuid: target_msg_data.get(2).unwrap().as_str().to_string(),
                    to_part: target_msg_data.get(1).unwrap().as_str().parse().unwrap(),
                    to_text: "".to_string(),
                    enable: enabled,
                    reaction: ReactMessage::from_idx(id)?,
                }),
            });
        }
        if let Ok(loaded) = plist::from_bytes::<RawIMessage>(&decompressed) {
            let msg_guid: Vec<u8> = wrapper.msg_guid.clone().into();
            let replies = loaded.reply.as_ref().map(|to| {
                let mut parts: Vec<&str> = to.split(":").collect();
                parts.remove(0); // remove r:
                let guididx = parts.iter().position(|p| p.contains("-")).unwrap();
                let guid = parts[guididx].to_string();
                parts.remove(guididx);
                (guid, parts.join(":"))
            });
            let parts = loaded
                .live_xml
                .as_ref()
                .or(loaded.xml.as_ref())
                .map_or_else(
                    || {
                        loaded
                            .text
                            .as_ref()
                            .map_or(MessageParts(vec![]), |text| MessageParts::from_raw(text))
                    },
                    |xml| MessageParts::parse_parts(xml, Some(&loaded)),
                );
            return Some(IMessage {
                sender: Some(wrapper.sender.clone()),
                id: Uuid::from_bytes(msg_guid.try_into().unwrap())
                    .to_string()
                    .to_uppercase(),
                after_guid: loaded.after_guid.clone(),
                sent_timestamp: wrapper.sent_timestamp / 1000000,
                conversation: Some(ConversationData {
                    participants: loaded.participants.clone(),
                    cv_name: loaded.cv_name.clone(),
                    sender_guid: loaded.sender_guid.clone(),
                }),
                message: Message::Message(NormalMessage {
                    parts,
                    body: if let Some(body) = &loaded.b {
                        if let Some(bid) = &loaded.bid {
                            Some(BalloonBody {
                                bid: bid.clone(),
                                data: body.clone().into(),
                            })
                        } else {
                            None
                        }
                    } else {
                        None
                    },
                    effect: loaded.effect.clone(),
                    reply_guid: replies.as_ref().map(|r| r.0.clone()),
                    reply_part: replies.as_ref().map(|r| r.1.clone()),
                }),
            });
        }
        None
    }
}

impl fmt::Display for IMessage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "[{}] '{}'",
            self.sender.clone().unwrap_or("unknown".to_string()),
            self.message
        )
    }
}
