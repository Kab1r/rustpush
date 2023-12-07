mod albert;
mod apns;
mod bags;
mod error;
mod ids;
mod imessage;
mod mmcs;
mod util;

pub mod mmcsp {
    include!(concat!(env!("OUT_DIR"), "/mmcsp.rs"));
}

pub use apns::{APNSConnection, APNSState};
pub use error::PushError;
pub use ids::{
    identity::register,
    user::{IDSAppleUser, IDSPhoneUser, IDSUser},
};
pub use imessage::client::{IMClient, RecievedMessage};
pub use imessage::messages::{
    Attachment, BalloonBody, ConversationData, IMessage, IconChangeMessage, IndexedMessagePart,
    MMCSFile, Message, MessagePart, MessageParts, NormalMessage, RenameMessage,
};
extern crate log;
extern crate pretty_env_logger;

//not sure if this can be called outside of this library and still have it work
pub fn init_logger() {
    let res = pretty_env_logger::try_init();
    if res.is_err() {
        println!("{}", res.unwrap_err())
    }
}
