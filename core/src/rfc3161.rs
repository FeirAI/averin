//! Real RFC 3161 TimeStampToken verification (feature `rfc3161`).
//!
//! A TimeStampToken is a CMS `SignedData` (RFC 5652) whose encapsulated content is a `TSTInfo`
//! (RFC 3161). Verification:
//!   1. parse `ContentInfo` -> `SignedData`; confirm eContentType is id-ct-TSTInfo;
//!   2. parse `TSTInfo` -> messageImprint (alg + hash) + genTime;
//!   3. verify the single `SignerInfo` signature over the signed attributes (or eContent) using the
//!      embedded TSA certificate's public key (ECDSA P-256 / SHA-256 in this build);
//!   4. confirm the message-digest signed attribute equals SHA-256(eContent).
//!
//! Trust of the TSA certificate itself reduces to a fingerprint the verifier pins out-of-band
//! (we do not walk an X.509 chain here — the relying party supplies the trusted TSA SPKI/cert).
//! This is feature-gated so the default + WASM builds stay lean.

use crate::hashx::sha256;
use der::asn1::{GeneralizedTime, ObjectIdentifier, OctetString};
use der::{Decode, Encode, Sequence};

const ID_SIGNED_DATA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.7.2");
const ID_CT_TST_INFO: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.16.1.4");
const ID_SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.1");
const ID_MESSAGE_DIGEST: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.4");
const ID_ECDSA_SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2");

#[derive(Debug, PartialEq)]
pub enum Rfc3161Error {
    Der(String),
    NotSignedData,
    NotTstInfo,
    NoSignerInfo,
    UnsupportedHash,
    UnsupportedSigAlg,
    MessageDigestMismatch,
    SignatureInvalid,
    ImprintMismatch,
}

impl std::fmt::Display for Rfc3161Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use Rfc3161Error::*;
        match self {
            Der(e) => write!(f, "DER decode error: {e}"),
            NotSignedData => write!(f, "ContentInfo is not signedData"),
            NotTstInfo => write!(f, "encapsulated content is not TSTInfo"),
            NoSignerInfo => write!(f, "no SignerInfo in token"),
            UnsupportedHash => write!(f, "unsupported messageImprint hash (expected SHA-256)"),
            UnsupportedSigAlg => {
                write!(f, "unsupported signature algorithm (expected ECDSA P-256)")
            }
            MessageDigestMismatch => write!(f, "message-digest attribute != hash(eContent)"),
            SignatureInvalid => write!(f, "TSA signature verification failed"),
            ImprintMismatch => write!(f, "messageImprint does not match the expected hash"),
        }
    }
}
impl std::error::Error for Rfc3161Error {}

fn der<E: std::fmt::Display>(e: E) -> Rfc3161Error {
    Rfc3161Error::Der(e.to_string())
}

/// RFC 3161 TSTInfo (trailing optional fields parsed-but-ignored via `der::Any`).
#[derive(Sequence)]
struct TstInfo {
    version: i32,
    policy: ObjectIdentifier,
    message_imprint: MessageImprint,
    serial_number: der::asn1::Int,
    gen_time: GeneralizedTime,
    #[asn1(optional = "true")]
    accuracy: Option<der::Any>,
    #[asn1(optional = "true")]
    ordering: Option<bool>,
    #[asn1(optional = "true")]
    nonce: Option<der::asn1::Int>,
    #[asn1(context_specific = "0", optional = "true", tag_mode = "EXPLICIT")]
    tsa: Option<der::Any>,
    #[asn1(context_specific = "1", optional = "true", tag_mode = "IMPLICIT")]
    extensions: Option<der::Any>,
}

#[derive(Sequence)]
struct MessageImprint {
    hash_algorithm: spki::AlgorithmIdentifierOwned,
    hashed_message: OctetString,
}

/// The verified facts extracted from a token.
#[derive(Debug, PartialEq)]
pub struct Verified {
    /// `genTime` as an RFC3339-ish string (the TSA's attested time).
    pub gen_time: String,
    /// The messageImprint hash bytes (SHA-256 of the anchored message).
    pub imprint: Vec<u8>,
}

/// Verify a DER TimeStampToken against a pinned TSA verifying key (ECDSA P-256). Confirms the CMS
/// signature, the message-digest binding, and returns genTime + the messageImprint. The caller
/// must additionally check the imprint equals the hash of the message it anchored (see
/// [`verify_binding`]).
pub fn verify_token(token_der: &[u8], tsa_spki_der: &[u8]) -> Result<Verified, Rfc3161Error> {
    use cms::content_info::ContentInfo;
    use cms::signed_data::SignedData;

    let ci = ContentInfo::from_der(token_der).map_err(der)?;
    if ci.content_type != ID_SIGNED_DATA {
        return Err(Rfc3161Error::NotSignedData);
    }
    let sd: SignedData = ci.content.decode_as().map_err(der)?;

    // encapsulated TSTInfo
    let eci = &sd.encap_content_info;
    if eci.econtent_type != ID_CT_TST_INFO {
        return Err(Rfc3161Error::NotTstInfo);
    }
    let econtent = eci.econtent.as_ref().ok_or(Rfc3161Error::NotTstInfo)?;
    // econtent is an Any wrapping an OCTET STRING whose bytes are the TSTInfo DER
    let tst_octets = econtent.decode_as::<OctetString>().map_err(der)?;
    let tst_bytes = tst_octets.as_bytes();
    let tst = TstInfo::from_der(tst_bytes).map_err(der)?;
    if tst.message_imprint.hash_algorithm.oid != ID_SHA256 {
        return Err(Rfc3161Error::UnsupportedHash);
    }
    let imprint = tst.message_imprint.hashed_message.as_bytes().to_vec();
    let dt = tst.gen_time.to_date_time();
    let gen_time = format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.000Z",
        dt.year(),
        dt.month(),
        dt.day(),
        dt.hour(),
        dt.minutes(),
        dt.seconds()
    );

    // signer
    let si = sd
        .signer_infos
        .0
        .as_slice()
        .first()
        .ok_or(Rfc3161Error::NoSignerInfo)?;

    // pin the algorithms declared in the SignerInfo (this build verifies only ECDSA-P256/SHA-256).
    if si.digest_alg.oid != ID_SHA256 {
        return Err(Rfc3161Error::UnsupportedHash);
    }
    if si.signature_algorithm.oid != ID_ECDSA_SHA256 {
        return Err(Rfc3161Error::UnsupportedSigAlg);
    }

    // to-be-signed bytes
    let tbs: Vec<u8> = match &si.signed_attrs {
        Some(attrs) => {
            // verify message-digest attr == sha256(eContent TSTInfo bytes)
            let want = sha256(tst_bytes);
            let mut md_ok = false;
            for attr in attrs.iter() {
                if attr.oid == ID_MESSAGE_DIGEST {
                    if let Some(val) = attr.values.iter().next() {
                        let octet = val.decode_as::<OctetString>().map_err(der)?;
                        md_ok = octet.as_bytes() == want;
                    }
                }
            }
            if !md_ok {
                return Err(Rfc3161Error::MessageDigestMismatch);
            }
            // RFC 5652: sign the DER SET OF (tag 0x31) of the signed attributes.
            attrs.to_der().map_err(der)?
        }
        None => tst_bytes.to_vec(),
    };

    // We verify against the pinned TSA SPKI supplied out-of-band, not the (optional) embedded cert
    // chain — chain validation is the relying party's policy.
    verify_ecdsa_p256(tsa_spki_der, &tbs, si.signature.as_bytes())?;

    Ok(Verified { gen_time, imprint })
}

fn verify_ecdsa_p256(spki_der: &[u8], msg: &[u8], sig_der: &[u8]) -> Result<(), Rfc3161Error> {
    use p256::ecdsa::signature::Verifier;
    use p256::ecdsa::{DerSignature, VerifyingKey};
    use spki::SubjectPublicKeyInfoRef;

    let spki = SubjectPublicKeyInfoRef::from_der(spki_der).map_err(der)?;
    let pub_bytes = spki
        .subject_public_key
        .as_bytes()
        .ok_or(Rfc3161Error::UnsupportedSigAlg)?;
    let vk =
        VerifyingKey::from_sec1_bytes(pub_bytes).map_err(|_| Rfc3161Error::UnsupportedSigAlg)?;
    let sig = DerSignature::from_bytes(sig_der).map_err(|_| Rfc3161Error::SignatureInvalid)?;
    vk.verify(msg, &sig)
        .map_err(|_| Rfc3161Error::SignatureInvalid)
}

/// Full check: verify the token signature AND that its messageImprint equals SHA-256(`message`).
pub fn verify_binding(
    token_der: &[u8],
    tsa_spki_der: &[u8],
    message: &[u8],
) -> Result<String, Rfc3161Error> {
    let v = verify_token(token_der, tsa_spki_der)?;
    if v.imprint != sha256(message) {
        return Err(Rfc3161Error::ImprintMismatch);
    }
    Ok(v.gen_time)
}

/// A hermetic mini-TSA: builds a genuine RFC 3161 TimeStampToken (CMS SignedData over TSTInfo,
/// signed-attributes profile, ECDSA P-256/SHA-256) over `message` at `gen_time`. Used by tests and
/// fixtures in lieu of a network TSA. Returns `(token_der, tsa_spki_der)`.
#[cfg(any(test, feature = "test-tsa"))]
pub fn make_test_token(message: &[u8], gen_time: &str, seed: &[u8; 32]) -> (Vec<u8>, Vec<u8>) {
    use cms::cert::IssuerAndSerialNumber;
    use cms::content_info::{CmsVersion, ContentInfo};
    use cms::signed_data::{
        CertificateSet, EncapsulatedContentInfo, SignedData, SignerIdentifier, SignerInfo,
        SignerInfos,
    };
    use der::asn1::{Any, Int, OctetString, SetOfVec};
    use der::{Encode, Tag};
    use p256::ecdsa::{signature::Signer, DerSignature, SigningKey};
    use p256::pkcs8::EncodePublicKey;
    use spki::AlgorithmIdentifierOwned;
    use x509_cert::attr::Attribute;
    use x509_cert::name::Name;
    use x509_cert::serial_number::SerialNumber;

    const ID_CONTENT_TYPE: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.3");
    const ECDSA_SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2");

    let sk = SigningKey::from_bytes(seed.into()).expect("p256 key");
    let spki_der = sk
        .verifying_key()
        .to_public_key_der()
        .unwrap()
        .as_bytes()
        .to_vec();

    let sha256_alg = AlgorithmIdentifierOwned {
        oid: ID_SHA256,
        parameters: None,
    };

    // TSTInfo
    let imprint = sha256(message);
    let tst = TstInfo {
        version: 1,
        policy: ObjectIdentifier::new_unwrap("1.2.3.4.1"),
        message_imprint: MessageImprint {
            hash_algorithm: sha256_alg.clone(),
            hashed_message: OctetString::new(imprint.to_vec()).unwrap(),
        },
        serial_number: Int::new(&[1]).unwrap(),
        gen_time: gen_time_to_asn1(gen_time),
        accuracy: None,
        ordering: None,
        nonce: None,
        tsa: None,
        extensions: None,
    };
    let tst_der = tst.to_der().unwrap();

    let encap = EncapsulatedContentInfo {
        econtent_type: ID_CT_TST_INFO,
        econtent: Some(Any::new(Tag::OctetString, tst_der.clone()).unwrap()),
    };

    // signed attributes: content-type + message-digest
    let md = sha256(&tst_der);
    let attr_ct = Attribute {
        oid: ID_CONTENT_TYPE,
        values: SetOfVec::try_from(vec![Any::encode_from(&ID_CT_TST_INFO).unwrap()]).unwrap(),
    };
    let md_any = Any::new(Tag::OctetString, md.to_vec()).unwrap();
    let attr_md = Attribute {
        oid: ID_MESSAGE_DIGEST,
        values: SetOfVec::try_from(vec![md_any]).unwrap(),
    };
    let signed_attrs: SetOfVec<Attribute> = SetOfVec::try_from(vec![attr_ct, attr_md]).unwrap();

    // sign the SET OF (0x31) DER of the signed attributes
    let signed_attrs_der = signed_attrs.to_der().unwrap();
    let sig: DerSignature = sk.sign(&signed_attrs_der);

    let signer = SignerInfo {
        version: CmsVersion::V1,
        sid: SignerIdentifier::IssuerAndSerialNumber(IssuerAndSerialNumber {
            issuer: Name::default(),
            serial_number: SerialNumber::new(&[1]).unwrap(),
        }),
        digest_alg: sha256_alg.clone(),
        signed_attrs: Some(signed_attrs),
        signature_algorithm: AlgorithmIdentifierOwned {
            oid: ECDSA_SHA256,
            parameters: None,
        },
        signature: OctetString::new(sig.to_bytes().to_vec()).unwrap(),
        unsigned_attrs: None,
    };

    let sd = SignedData {
        version: CmsVersion::V1,
        digest_algorithms: SetOfVec::try_from(vec![sha256_alg]).unwrap(),
        encap_content_info: encap,
        certificates: None::<CertificateSet>,
        crls: None,
        signer_infos: SignerInfos(SetOfVec::try_from(vec![signer]).unwrap()),
    };

    let ci = ContentInfo {
        content_type: ID_SIGNED_DATA,
        content: Any::encode_from(&sd).unwrap(),
    };
    (ci.to_der().unwrap(), spki_der)
}

#[cfg(any(test, feature = "test-tsa"))]
fn gen_time_to_asn1(ts: &str) -> GeneralizedTime {
    // ts = "YYYY-MM-DDThh:mm:ss.mmmZ"
    let n = |a: usize, b: usize| ts[a..b].parse::<u16>().unwrap();
    let dt = der::DateTime::new(
        n(0, 4),
        n(5, 7) as u8,
        n(8, 10) as u8,
        n(11, 13) as u8,
        n(14, 16) as u8,
        n(17, 19) as u8,
    )
    .unwrap();
    GeneralizedTime::from_date_time(dt)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn real_token_round_trips_and_binds() {
        let msg = b"sha256:deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef";
        let (token, spki) = make_test_token(msg, "2026-06-15T10:05:00.000Z", &[7u8; 32]);

        let v = verify_token(&token, &spki).expect("token verifies");
        assert_eq!(v.gen_time, "2026-06-15T10:05:00.000Z");
        assert_eq!(v.imprint, sha256(msg).to_vec());

        // full binding to the anchored message
        assert_eq!(
            verify_binding(&token, &spki, msg).unwrap(),
            "2026-06-15T10:05:00.000Z"
        );
        // wrong anchored message -> imprint mismatch
        assert_eq!(
            verify_binding(&token, &spki, b"other"),
            Err(Rfc3161Error::ImprintMismatch)
        );
    }

    #[test]
    fn wrong_tsa_key_rejected() {
        let msg = b"hello";
        let (token, _spki) = make_test_token(msg, "2026-06-15T10:05:00.000Z", &[7u8; 32]);
        let (_t2, other_spki) = make_test_token(b"x", "2026-06-15T10:05:00.000Z", &[9u8; 32]);
        assert_eq!(
            verify_token(&token, &other_spki),
            Err(Rfc3161Error::SignatureInvalid)
        );
    }

    #[test]
    fn corrupted_signature_is_rejected() {
        // The signature value is the trailing OCTET STRING of the token; flipping its last byte
        // must break the ECDSA verification. (Only signed-attrs/eContent are cryptographically
        // covered — that's CMS, so we corrupt a signed region, not arbitrary structural metadata.)
        let msg = b"hello";
        let (mut token, spki) = make_test_token(msg, "2026-06-15T10:05:00.000Z", &[7u8; 32]);
        let last = token.len() - 1;
        token[last] ^= 0x01;
        assert!(verify_token(&token, &spki).is_err());
    }

    #[test]
    fn gentime_is_faithfully_carried_and_bound() {
        // genTime lives in TSTInfo, committed via the message-digest signed attribute, so a token's
        // attested time is both reported and signature-bound.
        let msg = b"checkpoint-hash";
        let (t1, s1) = make_test_token(msg, "2026-06-15T10:00:00.000Z", &[3u8; 32]);
        let (t2, s2) = make_test_token(msg, "2026-06-15T11:30:45.000Z", &[3u8; 32]);
        assert_eq!(
            verify_binding(&t1, &s1, msg).unwrap(),
            "2026-06-15T10:00:00.000Z"
        );
        assert_eq!(
            verify_binding(&t2, &s2, msg).unwrap(),
            "2026-06-15T11:30:45.000Z"
        );
    }
}
