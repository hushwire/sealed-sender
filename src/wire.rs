use crate::error::{Error, Result};
use crate::sealed_sender::SealedEnvelope;
use crate::types::RecipientId;

/// Current wire format version.
pub const VERSION: u8 = 0x01;

pub const VERSION_LEN: usize = 1;
pub const RECIPIENT_LEN_LEN: usize = 2;
pub const MESSAGE_SEQ_LEN: usize = 8;
pub const EK_PUB_LEN: usize = 32;
pub const ENCRYPTED_STATIC_LEN: usize = 48;

/// Minimum bytes before the variable-length recipient ID.
pub const MIN_FIXED_OVERHEAD: usize =
    VERSION_LEN + RECIPIENT_LEN_LEN + MESSAGE_SEQ_LEN + EK_PUB_LEN + ENCRYPTED_STATIC_LEN;

/// A parsed sealed sender wire message with zero-copy references into the input bytes.
#[derive(Debug)]
#[allow(dead_code)]
pub struct DecodedMessage<'a, R: RecipientId> {
    pub recipient_id: R,
    pub message_sequence: u64,
    pub header_len: usize,
    pub ek_pub: [u8; 32],
    pub encrypted_static: &'a [u8],
    pub encrypted_message: &'a [u8],
}

/// Build the routing header bytes.
///
/// Layout: `version(1) | recipient_len(2 LE) | recipient_bytes(N) | message_sequence(8 LE)`
pub fn build_header<R: RecipientId>(recipient_id: &R, message_sequence: u64) -> Vec<u8> {
    let id_bytes = recipient_id.to_bytes();
    let mut header =
        Vec::with_capacity(VERSION_LEN + RECIPIENT_LEN_LEN + id_bytes.len() + MESSAGE_SEQ_LEN);
    header.push(VERSION);
    header.extend_from_slice(&(id_bytes.len() as u16).to_le_bytes());
    header.extend_from_slice(id_bytes);
    header.extend_from_slice(&message_sequence.to_le_bytes());
    header
}

/// Encode a sealed envelope with a pre-built routing header into wire-format bytes.
pub fn encode_with_header(header: &[u8], envelope: &SealedEnvelope) -> Vec<u8> {
    let mut out = Vec::with_capacity(
        header.len()
            + EK_PUB_LEN
            + envelope.encrypted_static.len()
            + envelope.encrypted_message.len(),
    );

    out.extend_from_slice(header);
    out.extend_from_slice(&envelope.ek_pub);
    out.extend_from_slice(&envelope.encrypted_static);
    out.extend_from_slice(&envelope.encrypted_message);

    out
}

#[cfg(test)]
pub fn encode<R: RecipientId>(
    recipient_id: &R,
    message_sequence: u64,
    envelope: &SealedEnvelope,
) -> Vec<u8> {
    let header = build_header(recipient_id, message_sequence);
    encode_with_header(&header, envelope)
}

/// Parse wire-format bytes into a [`DecodedMessage`] with zero-copy field references.
pub fn decode<R: RecipientId>(bytes: &[u8]) -> Result<DecodedMessage<'_, R>> {
    if bytes.len() < MIN_FIXED_OVERHEAD {
        return Err(Error::MessageTooShort);
    }

    let version = bytes[0];
    if version != VERSION {
        return Err(Error::UnknownVersion(version));
    }

    let mut offset = VERSION_LEN;

    let id_len = u16::from_le_bytes(
        bytes[offset..offset + RECIPIENT_LEN_LEN]
            .try_into()
            .map_err(|_| Error::MessageTooShort)?,
    ) as usize;
    offset += RECIPIENT_LEN_LEN;

    if bytes.len() < offset + id_len + MESSAGE_SEQ_LEN + EK_PUB_LEN + ENCRYPTED_STATIC_LEN {
        return Err(Error::MessageTooShort);
    }

    let recipient_id = R::from_bytes(&bytes[offset..offset + id_len])?;
    offset += id_len;

    let message_sequence = u64::from_le_bytes(
        bytes[offset..offset + MESSAGE_SEQ_LEN]
            .try_into()
            .map_err(|_| Error::MessageTooShort)?,
    );
    offset += MESSAGE_SEQ_LEN;

    let header_len = offset;

    let mut ek_pub = [0u8; 32];
    ek_pub.copy_from_slice(&bytes[offset..offset + EK_PUB_LEN]);
    offset += EK_PUB_LEN;

    let encrypted_static = &bytes[offset..offset + ENCRYPTED_STATIC_LEN];
    offset += ENCRYPTED_STATIC_LEN;

    let encrypted_message = &bytes[offset..];

    Ok(DecodedMessage {
        recipient_id,
        message_sequence,
        header_len,
        ek_pub,
        encrypted_static,
        encrypted_message,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::Recipient;

    fn test_envelope() -> SealedEnvelope {
        SealedEnvelope {
            ek_pub: [0xAA; 32],
            encrypted_static: vec![0xBB; ENCRYPTED_STATIC_LEN],
            encrypted_message: vec![0xCC; 100],
        }
    }

    fn rid(b: u8) -> Recipient {
        Recipient::from_bytes_copy(&[b; 16])
    }

    #[test]
    fn encode_decode_roundtrip() {
        let recipient = rid(0x42);
        let seq = 7u64;
        let envelope = test_envelope();

        let wire = encode(&recipient, seq, &envelope);
        let decoded: DecodedMessage<Recipient> = decode(&wire).unwrap();

        assert_eq!(decoded.recipient_id, recipient);
        assert_eq!(decoded.message_sequence, seq);
        assert_eq!(decoded.ek_pub, [0xAA; 32]);
        assert_eq!(decoded.encrypted_static, &[0xBB; ENCRYPTED_STATIC_LEN]);
        assert_eq!(decoded.encrypted_message, &[0xCC; 100]);
    }

    #[test]
    fn version_byte_is_first() {
        let wire = encode(&rid(0), 0, &test_envelope());
        assert_eq!(wire[0], VERSION);
    }

    #[test]
    fn byte_layout_matches_spec() {
        let recipient = Recipient::from_bytes_copy(&[0x22; 16]);
        let seq: u64 = 0x0807060504030201;
        let envelope = test_envelope();

        let wire = encode(&recipient, seq, &envelope);

        let mut offset = 0;
        assert_eq!(wire[offset], 0x01); // version
        offset += 1;
        assert_eq!(&wire[offset..offset + 2], &16u16.to_le_bytes()); // recipient len
        offset += 2;
        assert_eq!(&wire[offset..offset + 16], &[0x22; 16]); // recipient bytes
        offset += 16;
        assert_eq!(
            &wire[offset..offset + 8],
            &[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]
        ); // message_sequence LE
        offset += 8;
        assert_eq!(&wire[offset..offset + 32], &[0xAA; 32]); // ek_pub
        offset += 32;
        assert_eq!(&wire[offset..offset + 48], &[0xBB; 48]); // encrypted_static
        offset += 48;
        assert_eq!(&wire[offset..], &[0xCC; 100]); // encrypted_message
    }

    #[test]
    fn rejects_truncated_input() {
        let wire = vec![0u8; MIN_FIXED_OVERHEAD - 1];
        let err = decode::<Recipient>(&wire).unwrap_err();
        assert!(matches!(err, Error::MessageTooShort));
    }

    #[test]
    fn rejects_wrong_version() {
        let mut wire = encode(&rid(0), 0, &test_envelope());
        wire[0] = 0x99;
        let err = decode::<Recipient>(&wire).unwrap_err();
        assert!(matches!(err, Error::UnknownVersion(0x99)));
    }

    #[test]
    fn accepts_minimum_size() {
        let envelope = SealedEnvelope {
            ek_pub: [0; 32],
            encrypted_static: vec![0; ENCRYPTED_STATIC_LEN],
            encrypted_message: vec![],
        };
        let wire = encode(&rid(0), 0, &envelope);
        decode::<Recipient>(&wire).unwrap();
    }

    #[test]
    fn variable_length_recipient_id() {
        let short_id = Recipient::from_bytes_copy(&[0xAA; 4]);
        let long_id = Recipient::from_bytes_copy(&[0xBB; 64]);
        let envelope = test_envelope();

        let wire_short = encode(&short_id, 1, &envelope);
        let wire_long = encode(&long_id, 1, &envelope);

        assert!(wire_long.len() > wire_short.len());

        let decoded_short: DecodedMessage<Recipient> = decode(&wire_short).unwrap();
        let decoded_long: DecodedMessage<Recipient> = decode(&wire_long).unwrap();

        assert_eq!(decoded_short.recipient_id, short_id);
        assert_eq!(decoded_long.recipient_id, long_id);
    }
}
