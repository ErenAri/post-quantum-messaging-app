use crate::tlv::{critical_type, encode, TlvRecord};
use crate::CoreError;

const CONTEXT_VERSION: u16 = 1;
const TAG_CONTEXT_VERSION: u16 = critical_type(0x1201);
const TAG_SENDER_ID: u16 = critical_type(0x1202);
const TAG_RECIPIENT_ID: u16 = critical_type(0x1203);

pub fn conversation_associated_data(
    sender_user_id: &str,
    recipient_user_id: &str,
) -> Result<Vec<u8>, CoreError> {
    encode(&[
        TlvRecord {
            ty: TAG_CONTEXT_VERSION,
            value: CONTEXT_VERSION.to_be_bytes().to_vec(),
        },
        TlvRecord {
            ty: TAG_SENDER_ID,
            value: sender_user_id.as_bytes().to_vec(),
        },
        TlvRecord {
            ty: TAG_RECIPIENT_ID,
            value: recipient_user_id.as_bytes().to_vec(),
        },
    ])
}

#[cfg(test)]
mod tests {
    use super::conversation_associated_data;

    #[test]
    fn ad_is_deterministic() {
        let a = conversation_associated_data("alice", "bob").expect("ad");
        let b = conversation_associated_data("alice", "bob").expect("ad");
        assert_eq!(a, b);
    }
}
