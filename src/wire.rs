use crate::error::{Error, Result};
use crate::sealed_sender::SealedEnvelope;
use crate::types::{DeviceId, UserId};

pub const VERSION: u8 = 0x01;

pub const VERSION_LEN: usize = 1;
pub const USER_ID_LEN: usize = 16;
pub const DEVICE_ID_LEN: usize = 4;
pub const EK_PUB_LEN: usize = 32;
pub const ENCRYPTED_STATIC_LEN: usize = 48; // 32 ct + 16 tag

pub const HEADER_LEN: usize = VERSION_LEN + USER_ID_LEN + DEVICE_ID_LEN;
pub const MIN_MESSAGE_LEN: usize = HEADER_LEN + EK_PUB_LEN + ENCRYPTED_STATIC_LEN;

#[derive(Debug)]
pub struct DecodedMessage<'a> {
    pub recipient_id: UserId,
    pub recipient_device_id: DeviceId,
    pub ek_pub: [u8; 32],
    pub encrypted_static: &'a [u8],
    pub encrypted_message: &'a [u8],
}

pub fn encode(
    recipient_id: UserId,
    recipient_device_id: DeviceId,
    envelope: &SealedEnvelope,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(
        HEADER_LEN
            + EK_PUB_LEN
            + envelope.encrypted_static.len()
            + envelope.encrypted_message.len(),
    );

    out.push(VERSION);
    out.extend_from_slice(recipient_id.as_bytes());
    out.extend_from_slice(&recipient_device_id.as_u32().to_le_bytes());
    out.extend_from_slice(&envelope.ek_pub);
    out.extend_from_slice(&envelope.encrypted_static);
    out.extend_from_slice(&envelope.encrypted_message);

    out
}

pub fn decode(bytes: &[u8]) -> Result<DecodedMessage<'_>> {
    if bytes.len() < MIN_MESSAGE_LEN {
        return Err(Error::MessageTooShort);
    }

    let version = bytes[0];
    if version != VERSION {
        return Err(Error::UnknownVersion(version));
    }

    let mut offset = VERSION_LEN;

    let mut recipient_id_bytes = [0u8; 16];
    recipient_id_bytes.copy_from_slice(&bytes[offset..offset + USER_ID_LEN]);
    offset += USER_ID_LEN;

    let device_id = u32::from_le_bytes(bytes[offset..offset + DEVICE_ID_LEN].try_into().unwrap());
    offset += DEVICE_ID_LEN;

    let mut ek_pub = [0u8; 32];
    ek_pub.copy_from_slice(&bytes[offset..offset + EK_PUB_LEN]);
    offset += EK_PUB_LEN;

    let encrypted_static = &bytes[offset..offset + ENCRYPTED_STATIC_LEN];
    offset += ENCRYPTED_STATIC_LEN;

    let encrypted_message = &bytes[offset..];

    Ok(DecodedMessage {
        recipient_id: UserId::from_bytes(recipient_id_bytes),
        recipient_device_id: DeviceId::new(device_id),
        ek_pub,
        encrypted_static,
        encrypted_message,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_envelope() -> SealedEnvelope {
        SealedEnvelope {
            ek_pub: [0xAA; 32],
            encrypted_static: vec![0xBB; ENCRYPTED_STATIC_LEN],
            encrypted_message: vec![0xCC; 100],
        }
    }

    #[test]
    fn encode_decode_roundtrip() {
        let recipient_id = UserId::from_bytes([1u8; 16]);
        let device_id = DeviceId::new(42);
        let envelope = test_envelope();

        let wire = encode(recipient_id, device_id, &envelope);
        let decoded = decode(&wire).unwrap();

        assert_eq!(decoded.recipient_id, recipient_id);
        assert_eq!(decoded.recipient_device_id, device_id);
        assert_eq!(decoded.ek_pub, [0xAA; 32]);
        assert_eq!(decoded.encrypted_static, &[0xBB; ENCRYPTED_STATIC_LEN]);
        assert_eq!(decoded.encrypted_message, &[0xCC; 100]);
    }

    #[test]
    fn version_byte_is_first() {
        let wire = encode(
            UserId::from_bytes([0; 16]),
            DeviceId::new(0),
            &test_envelope(),
        );
        assert_eq!(wire[0], VERSION);
    }

    #[test]
    fn byte_layout_matches_spec() {
        let recipient_id = UserId::from_bytes([0x11; 16]);
        let device_id = DeviceId::new(0x04030201);
        let envelope = test_envelope();

        let wire = encode(recipient_id, device_id, &envelope);

        assert_eq!(wire[0], 0x01); // version
        assert_eq!(&wire[1..17], &[0x11; 16]); // recipient_id
        assert_eq!(&wire[17..21], &[0x01, 0x02, 0x03, 0x04]); // device_id LE
        assert_eq!(&wire[21..53], &[0xAA; 32]); // ek_pub
        assert_eq!(&wire[53..101], &[0xBB; 48]); // encrypted_static
        assert_eq!(&wire[101..], &[0xCC; 100]); // encrypted_message
    }

    #[test]
    fn rejects_truncated_input() {
        let wire = vec![0u8; MIN_MESSAGE_LEN - 1];
        let err = decode(&wire).unwrap_err();
        assert!(matches!(err, Error::MessageTooShort));
    }

    #[test]
    fn rejects_wrong_version() {
        let mut wire = encode(
            UserId::from_bytes([0; 16]),
            DeviceId::new(0),
            &test_envelope(),
        );
        wire[0] = 0x99;
        let err = decode(&wire).unwrap_err();
        assert!(matches!(err, Error::UnknownVersion(0x99)));
    }

    #[test]
    fn accepts_minimum_size() {
        let envelope = SealedEnvelope {
            ek_pub: [0; 32],
            encrypted_static: vec![0; ENCRYPTED_STATIC_LEN],
            encrypted_message: vec![],
        };
        let wire = encode(UserId::from_bytes([0; 16]), DeviceId::new(0), &envelope);
        assert_eq!(wire.len(), MIN_MESSAGE_LEN);
        decode(&wire).unwrap();
    }
}
