//! Real RFC 3161 TimeStampToken verification (feature `rfc3161`).
//!
//! A TimeStampToken is a CMS `SignedData` (RFC 5652) whose encapsulated content is a `TSTInfo`
//! (RFC 3161). Verification:
//!   1. parse `ContentInfo` -> `SignedData`; confirm eContentType is id-ct-TSTInfo;
//!   2. parse `TSTInfo` -> messageImprint (alg + hash) + genTime;
//!   3. verify the single `SignerInfo` signature over the signed attributes (or eContent) using the
//!      operator-pinned TSA public key (ECDSA P-256/SHA-256, ECDSA P-384/SHA-512, RSA PKCS#1 v1.5 or
//!      RSASSA-PSS with SHA-256/384/512, RSA keys of at least 2048 bits);
//!   4. confirm the message-digest signed attribute equals the SignerInfo digest of eContent.
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
const ID_SHA512: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.3");
const ID_MESSAGE_DIGEST: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.4");
const ID_ECDSA_SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2");
const ID_ECDSA_SHA512: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.4");

const ID_SHA384: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.2");
const ID_RSA_ENCRYPTION: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.1");
const ID_SHA256_RSA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.11");
const ID_SHA384_RSA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.12");
const ID_SHA512_RSA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.13");
const ID_RSASSA_PSS: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.10");
const ID_MGF1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.8");
/// RSA keys below this size are refused: a TSA key that small can be factored.
const MIN_RSA_BITS: usize = 2048;

#[derive(Clone, Copy, PartialEq, Debug)]
enum HashAlg {
    Sha256,
    Sha384,
    Sha512,
}

impl HashAlg {
    fn from_oid(o: &ObjectIdentifier) -> Option<Self> {
        if *o == ID_SHA256 {
            Some(Self::Sha256)
        } else if *o == ID_SHA384 {
            Some(Self::Sha384)
        } else if *o == ID_SHA512 {
            Some(Self::Sha512)
        } else {
            None
        }
    }
    fn digest(self, data: &[u8]) -> Vec<u8> {
        use sha2::Digest;
        match self {
            Self::Sha256 => sha2::Sha256::digest(data).to_vec(),
            Self::Sha384 => sha2::Sha384::digest(data).to_vec(),
            Self::Sha512 => sha2::Sha512::digest(data).to_vec(),
        }
    }
}

/// The accepted TSA signature profiles. Anything else is `UnsupportedSigAlg` (fail closed).
#[derive(Debug, PartialEq)]
enum SigScheme {
    EcdsaP256Sha256,
    EcdsaP384Sha512,
    RsaPkcs1,
    RsaPss { salt_len: usize },
}

/// RSASSA-PSS-params (RFC 4055). Absent fields take the RFC defaults (SHA-1), which we refuse.
#[derive(Sequence)]
struct PssParams {
    #[asn1(context_specific = "0", optional = "true", tag_mode = "EXPLICIT")]
    hash: Option<spki::AlgorithmIdentifierOwned>,
    #[asn1(context_specific = "1", optional = "true", tag_mode = "EXPLICIT")]
    mgf: Option<spki::AlgorithmIdentifierOwned>,
    #[asn1(context_specific = "2", optional = "true", tag_mode = "EXPLICIT")]
    salt_len: Option<u32>,
    #[asn1(context_specific = "3", optional = "true", tag_mode = "EXPLICIT")]
    trailer: Option<u32>,
}

impl SigScheme {
    fn select(
        sig_oid: &ObjectIdentifier,
        params: Option<&der::Any>,
        hash: HashAlg,
    ) -> Result<Self, Rfc3161Error> {
        let o = *sig_oid;
        if o == ID_ECDSA_SHA256 && hash == HashAlg::Sha256 {
            return Ok(Self::EcdsaP256Sha256);
        }
        if o == ID_ECDSA_SHA512 && hash == HashAlg::Sha512 {
            return Ok(Self::EcdsaP384Sha512);
        }
        // PKCS#1 v1.5: the algorithm OID may name the hash, or be bare rsaEncryption (CMS allows
        // both; the SignerInfo digestAlgorithm then fixes the hash). A named hash must agree.
        let named = if o == ID_SHA256_RSA {
            Some(HashAlg::Sha256)
        } else if o == ID_SHA384_RSA {
            Some(HashAlg::Sha384)
        } else if o == ID_SHA512_RSA {
            Some(HashAlg::Sha512)
        } else {
            None
        };
        if let Some(h) = named {
            return if h == hash {
                Ok(Self::RsaPkcs1)
            } else {
                Err(Rfc3161Error::UnsupportedSigAlg)
            };
        }
        if o == ID_RSA_ENCRYPTION {
            return Ok(Self::RsaPkcs1);
        }
        if o == ID_RSASSA_PSS {
            let any = params.ok_or(Rfc3161Error::UnsupportedSigAlg)?;
            let p: PssParams = any
                .decode_as()
                .map_err(|_| Rfc3161Error::UnsupportedSigAlg)?;
            let ph = p
                .hash
                .as_ref()
                .and_then(|a| HashAlg::from_oid(&a.oid))
                .ok_or(Rfc3161Error::UnsupportedSigAlg)?;
            let mgf = p.mgf.ok_or(Rfc3161Error::UnsupportedSigAlg)?;
            if mgf.oid != ID_MGF1 {
                return Err(Rfc3161Error::UnsupportedSigAlg);
            }
            let mgf_hash = mgf
                .parameters
                .as_ref()
                .and_then(|x| x.decode_as::<spki::AlgorithmIdentifierOwned>().ok())
                .and_then(|a| HashAlg::from_oid(&a.oid))
                .ok_or(Rfc3161Error::UnsupportedSigAlg)?;
            if ph != hash || mgf_hash != hash || p.trailer.unwrap_or(1) != 1 {
                return Err(Rfc3161Error::UnsupportedSigAlg);
            }
            let salt_len = p.salt_len.unwrap_or(20) as usize;
            // A salt longer than the hash is not used by any TSA and only widens the parser.
            if salt_len > 64 {
                return Err(Rfc3161Error::UnsupportedSigAlg);
            }
            return Ok(Self::RsaPss { salt_len });
        }
        Err(Rfc3161Error::UnsupportedSigAlg)
    }
}

fn verify_rsa(
    spki_der: &[u8],
    hash: HashAlg,
    prehash: &[u8],
    sig: &[u8],
    pss_salt: Option<usize>,
) -> Result<(), Rfc3161Error> {
    use rsa::pkcs8::DecodePublicKey;
    use rsa::traits::PublicKeyParts;
    use rsa::{Pkcs1v15Sign, Pss, RsaPublicKey};

    let key =
        RsaPublicKey::from_public_key_der(spki_der).map_err(|_| Rfc3161Error::UnsupportedSigAlg)?;
    if key.n().bits() < MIN_RSA_BITS {
        return Err(Rfc3161Error::UnsupportedSigAlg);
    }
    let r = match (pss_salt, hash) {
        (None, HashAlg::Sha256) => key.verify(Pkcs1v15Sign::new::<sha2::Sha256>(), prehash, sig),
        (None, HashAlg::Sha384) => key.verify(Pkcs1v15Sign::new::<sha2::Sha384>(), prehash, sig),
        (None, HashAlg::Sha512) => key.verify(Pkcs1v15Sign::new::<sha2::Sha512>(), prehash, sig),
        (Some(n), HashAlg::Sha256) => {
            key.verify(Pss::new_with_salt::<sha2::Sha256>(n), prehash, sig)
        }
        (Some(n), HashAlg::Sha384) => {
            key.verify(Pss::new_with_salt::<sha2::Sha384>(n), prehash, sig)
        }
        (Some(n), HashAlg::Sha512) => {
            key.verify(Pss::new_with_salt::<sha2::Sha512>(n), prehash, sig)
        }
    };
    r.map_err(|_| Rfc3161Error::SignatureInvalid)
}

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
            UnsupportedHash => write!(
                f,
                "unsupported messageImprint hash (expected SHA-256/384/512)"
            ),
            UnsupportedSigAlg => {
                write!(f, "unsupported signature algorithm (expected ECDSA P-256/P-384 or RSA >= 2048 bits)")
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

    // Pin the supported TSA signing profiles. The timestamp request's messageImprint remains SHA-256;
    // the SignerInfo digest below is over TSTInfo and may independently be SHA-256/384/512.
    let hash = HashAlg::from_oid(&si.digest_alg.oid).ok_or(Rfc3161Error::UnsupportedHash)?;
    let scheme = SigScheme::select(
        &si.signature_algorithm.oid,
        si.signature_algorithm.parameters.as_ref(),
        hash,
    )?;

    // to-be-signed bytes
    let tbs: Vec<u8> = match &si.signed_attrs {
        Some(attrs) => {
            // verify message-digest attr == hash(eContent TSTInfo bytes)
            let want = hash.digest(tst_bytes);
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
    // chain: chain validation is the relying party's policy.
    let sig = si.signature.as_bytes();
    match scheme {
        SigScheme::EcdsaP256Sha256 => verify_ecdsa_p256(tsa_spki_der, &tbs, sig)?,
        SigScheme::EcdsaP384Sha512 => verify_ecdsa_p384(tsa_spki_der, &tbs, sig)?,
        SigScheme::RsaPkcs1 => verify_rsa(tsa_spki_der, hash, &hash.digest(&tbs), sig, None)?,
        SigScheme::RsaPss { salt_len } => {
            verify_rsa(tsa_spki_der, hash, &hash.digest(&tbs), sig, Some(salt_len))?
        }
    }

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

fn verify_ecdsa_p384(spki_der: &[u8], msg: &[u8], sig_der: &[u8]) -> Result<(), Rfc3161Error> {
    use p384::ecdsa::signature::hazmat::PrehashVerifier;
    use p384::ecdsa::{Signature, VerifyingKey};
    use sha2::Digest;
    use spki::SubjectPublicKeyInfoRef;

    let spki = SubjectPublicKeyInfoRef::from_der(spki_der).map_err(der)?;
    let pub_bytes = spki
        .subject_public_key
        .as_bytes()
        .ok_or(Rfc3161Error::UnsupportedSigAlg)?;
    let vk =
        VerifyingKey::from_sec1_bytes(pub_bytes).map_err(|_| Rfc3161Error::UnsupportedSigAlg)?;
    let sig = Signature::from_der(sig_der).map_err(|_| Rfc3161Error::SignatureInvalid)?;
    vk.verify_prehash(&sha2::Sha512::digest(msg), &sig)
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
    use p256::ecdsa::{signature::Signer, DerSignature, SigningKey};
    use p256::pkcs8::EncodePublicKey;

    let sk = SigningKey::from_bytes(seed.into()).expect("p256 key");
    let spki_der = sk
        .verifying_key()
        .to_public_key_der()
        .unwrap()
        .as_bytes()
        .to_vec();
    let token = build_cms_token(
        message,
        gen_time,
        HashAlg::Sha256,
        spki::AlgorithmIdentifierOwned {
            oid: ID_ECDSA_SHA256,
            parameters: None,
        },
        &|tbs| {
            let sig: DerSignature = sk.sign(tbs);
            sig.to_bytes().to_vec()
        },
    );
    (token, spki_der)
}

/// Assemble a TimeStampToken whose SignerInfo uses `hash` and `sig_alg`, signing the DER signed
/// attributes with `sign`. The shared builder behind the hermetic tokens in the tests.
#[cfg(any(test, feature = "test-tsa"))]
fn build_cms_token(
    message: &[u8],
    gen_time: &str,
    hash: HashAlg,
    sig_alg: spki::AlgorithmIdentifierOwned,
    sign: &dyn Fn(&[u8]) -> Vec<u8>,
) -> Vec<u8> {
    use cms::cert::IssuerAndSerialNumber;
    use cms::content_info::{CmsVersion, ContentInfo};
    use cms::signed_data::{
        CertificateSet, EncapsulatedContentInfo, SignedData, SignerIdentifier, SignerInfo,
        SignerInfos,
    };
    use der::asn1::{Any, Int, OctetString, SetOfVec};
    use der::{Encode, Tag};
    use spki::AlgorithmIdentifierOwned;
    use x509_cert::attr::Attribute;
    use x509_cert::name::Name;
    use x509_cert::serial_number::SerialNumber;

    const ID_CONTENT_TYPE: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.3");

    let sha256_alg = AlgorithmIdentifierOwned {
        oid: ID_SHA256,
        parameters: None,
    };
    let digest_oid = match hash {
        HashAlg::Sha256 => ID_SHA256,
        HashAlg::Sha384 => ID_SHA384,
        HashAlg::Sha512 => ID_SHA512,
    };
    let digest_alg = AlgorithmIdentifierOwned {
        oid: digest_oid,
        parameters: None,
    };

    // TSTInfo (the request messageImprint is always SHA-256)
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
    let md = hash.digest(&tst_der);
    let attr_ct = Attribute {
        oid: ID_CONTENT_TYPE,
        values: SetOfVec::try_from(vec![Any::encode_from(&ID_CT_TST_INFO).unwrap()]).unwrap(),
    };
    let md_any = Any::new(Tag::OctetString, md).unwrap();
    let attr_md = Attribute {
        oid: ID_MESSAGE_DIGEST,
        values: SetOfVec::try_from(vec![md_any]).unwrap(),
    };
    let signed_attrs: SetOfVec<Attribute> = SetOfVec::try_from(vec![attr_ct, attr_md]).unwrap();

    // sign the SET OF (0x31) DER of the signed attributes
    let signed_attrs_der = signed_attrs.to_der().unwrap();
    let sig = sign(&signed_attrs_der);

    let signer = SignerInfo {
        version: CmsVersion::V1,
        sid: SignerIdentifier::IssuerAndSerialNumber(IssuerAndSerialNumber {
            issuer: Name::default(),
            serial_number: SerialNumber::new(&[1]).unwrap(),
        }),
        digest_alg: digest_alg.clone(),
        signed_attrs: Some(signed_attrs),
        signature_algorithm: sig_alg,
        signature: OctetString::new(sig).unwrap(),
        unsigned_attrs: None,
    };

    let sd = SignedData {
        version: CmsVersion::V1,
        digest_algorithms: SetOfVec::try_from(vec![digest_alg]).unwrap(),
        encap_content_info: encap,
        certificates: None::<CertificateSet>,
        crls: None,
        signer_infos: SignerInfos(SetOfVec::try_from(vec![signer]).unwrap()),
    };

    let ci = ContentInfo {
        content_type: ID_SIGNED_DATA,
        content: Any::encode_from(&sd).unwrap(),
    };
    ci.to_der().unwrap()
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
    fn p384_sha512_signature_profile_verifies() {
        use p384::ecdsa::signature::hazmat::PrehashSigner;
        use p384::ecdsa::{Signature, SigningKey};
        use p384::pkcs8::EncodePublicKey;
        use sha2::Digest;

        let sk = SigningKey::from_bytes((&[11u8; 48]).into()).expect("fixed P-384 key");
        let msg = b"freeTSA-style CMS signed attributes";
        let sig: Signature = sk
            .sign_prehash(&sha2::Sha512::digest(msg))
            .expect("P-384/SHA-512 sign");
        let spki = sk.verifying_key().to_public_key_der().expect("P-384 SPKI");
        let sig_der = sig.to_der();
        verify_ecdsa_p384(spki.as_bytes(), msg, sig_der.as_bytes())
            .expect("P-384/SHA-512 verifies");
        assert_eq!(
            verify_ecdsa_p384(spki.as_bytes(), b"changed", sig_der.as_bytes()),
            Err(Rfc3161Error::SignatureInvalid)
        );
    }

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

    // ---- AVE-03: recorded real TSA responses -------------------------------------------------
    // Each fixture is the TimeStampToken from a live request made on 2026-10-15 (see
    // core/tests/fixtures/tsa/README.md): FreeTSA signs with ECDSA P-384/SHA-512, DigiCert with
    // RSA PKCS#1 v1.5/SHA-256, Sectigo with RSA PKCS#1 v1.5/SHA-384. The SPKI is the TSA signing
    // certificate's key, which is what an operator pins.
    const REC_MSG: &[u8] = include_bytes!("../tests/fixtures/tsa/message.txt");

    fn recorded(name: &str) -> (&'static [u8], &'static [u8]) {
        match name {
            "freetsa" => (
                include_bytes!("../tests/fixtures/tsa/freetsa.token.der"),
                include_bytes!("../tests/fixtures/tsa/freetsa.spki.der"),
            ),
            "digicert" => (
                include_bytes!("../tests/fixtures/tsa/digicert.token.der"),
                include_bytes!("../tests/fixtures/tsa/digicert.spki.der"),
            ),
            _ => (
                include_bytes!("../tests/fixtures/tsa/sectigo.token.der"),
                include_bytes!("../tests/fixtures/tsa/sectigo.spki.der"),
            ),
        }
    }

    #[test]
    fn recorded_real_tsa_tokens_verify_and_bind() {
        for (name, time) in [
            ("freetsa", "2026-10-15T07:26:44.000Z"),
            ("digicert", "2026-10-15T07:26:49.000Z"),
            ("sectigo", "2026-10-15T07:26:50.000Z"),
        ] {
            let (token, spki) = recorded(name);
            assert_eq!(
                verify_binding(token, spki, REC_MSG).as_deref(),
                Ok(time),
                "{name}"
            );
            assert_eq!(
                verify_binding(token, spki, b"not the stamped message"),
                Err(Rfc3161Error::ImprintMismatch),
                "{name}"
            );
        }
    }

    #[test]
    fn recorded_real_tokens_fail_under_another_tsas_key() {
        for (tok, key) in [
            ("digicert", "sectigo"),
            ("sectigo", "digicert"),
            ("digicert", "freetsa"),
            ("freetsa", "digicert"),
        ] {
            let (token, _) = recorded(tok);
            let (_, spki) = recorded(key);
            assert!(
                verify_token(token, spki).is_err(),
                "{tok} under {key}'s key"
            );
        }
    }

    #[test]
    fn recorded_rsa_token_with_flipped_signature_bit_is_rejected() {
        for name in ["digicert", "sectigo"] {
            let (token, spki) = recorded(name);
            // locate the RSA signature (the last 512-byte OCTET STRING of the SignerInfo) by search:
            // flip a bit inside the signature value, found as the longest 0x04 0x82 0x02 0x00 run.
            let mut t = token.to_vec();
            let pos = t
                .windows(4)
                .rposition(|w| w == [0x04, 0x82, 0x02, 0x00] || w == [0x04, 0x82, 0x01, 0x00])
                .expect("signature octet string");
            t[pos + 4 + 10] ^= 0x01;
            assert_eq!(
                verify_token(&t, spki),
                Err(Rfc3161Error::SignatureInvalid),
                "{name}"
            );
        }
    }

    // ---- synthetic RSA tokens: PSS and PKCS#1 v1.5 with every hash ---------------------------
    struct CountRng(u64);
    impl rsa::rand_core::RngCore for CountRng {
        fn next_u32(&mut self) -> u32 {
            self.next_u64() as u32
        }
        fn next_u64(&mut self) -> u64 {
            // splitmix64: deterministic, test only
            self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
            let mut z = self.0;
            z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
            z ^ (z >> 31)
        }
        fn fill_bytes(&mut self, dest: &mut [u8]) {
            for c in dest.chunks_mut(8) {
                let v = self.next_u64().to_le_bytes();
                c.copy_from_slice(&v[..c.len()]);
            }
        }
        fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rsa::rand_core::Error> {
            self.fill_bytes(dest);
            Ok(())
        }
    }
    impl rsa::rand_core::CryptoRng for CountRng {}

    fn rsa_key(bits: usize, seed: u64) -> (rsa::RsaPrivateKey, Vec<u8>) {
        use rsa::pkcs8::EncodePublicKey;
        let sk = rsa::RsaPrivateKey::new(&mut CountRng(seed), bits).expect("rsa key");
        let spki = rsa::RsaPublicKey::from(&sk)
            .to_public_key_der()
            .unwrap()
            .as_bytes()
            .to_vec();
        (sk, spki)
    }

    fn sign_rsa(
        sk: &rsa::RsaPrivateKey,
        hash: HashAlg,
        pss_salt: Option<usize>,
        tbs: &[u8],
    ) -> Vec<u8> {
        use rsa::{Pkcs1v15Sign, Pss};
        let h = hash.digest(tbs);
        let mut rng = CountRng(99);
        match (pss_salt, hash) {
            (None, HashAlg::Sha256) => sk.sign(Pkcs1v15Sign::new::<sha2::Sha256>(), &h),
            (None, HashAlg::Sha384) => sk.sign(Pkcs1v15Sign::new::<sha2::Sha384>(), &h),
            (None, HashAlg::Sha512) => sk.sign(Pkcs1v15Sign::new::<sha2::Sha512>(), &h),
            (Some(n), HashAlg::Sha256) => {
                sk.sign_with_rng(&mut rng, Pss::new_with_salt::<sha2::Sha256>(n), &h)
            }
            (Some(n), HashAlg::Sha384) => {
                sk.sign_with_rng(&mut rng, Pss::new_with_salt::<sha2::Sha384>(n), &h)
            }
            (Some(n), HashAlg::Sha512) => {
                sk.sign_with_rng(&mut rng, Pss::new_with_salt::<sha2::Sha512>(n), &h)
            }
        }
        .expect("rsa sign")
    }

    fn hash_oid(h: HashAlg) -> ObjectIdentifier {
        match h {
            HashAlg::Sha256 => ID_SHA256,
            HashAlg::Sha384 => ID_SHA384,
            HashAlg::Sha512 => ID_SHA512,
        }
    }

    fn pss_alg(h: HashAlg, salt: u32) -> spki::AlgorithmIdentifierOwned {
        pss_alg_with(h, h, salt)
    }

    /// PSS parameters naming hash `h` with an MGF1 over `mgf_h` (a TSA that mixes them is refused).
    fn pss_alg_with(h: HashAlg, mgf_h: HashAlg, salt: u32) -> spki::AlgorithmIdentifierOwned {
        let alg = |oid| spki::AlgorithmIdentifierOwned {
            oid,
            parameters: None,
        };
        let mgf = spki::AlgorithmIdentifierOwned {
            oid: ID_MGF1,
            parameters: Some(der::Any::encode_from(&alg(hash_oid(mgf_h))).unwrap()),
        };
        let params = PssParams {
            hash: Some(alg(hash_oid(h))),
            mgf: Some(mgf),
            salt_len: Some(salt),
            trailer: None,
        };
        spki::AlgorithmIdentifierOwned {
            oid: ID_RSASSA_PSS,
            parameters: Some(der::Any::encode_from(&params).unwrap()),
        }
    }

    fn rsa_token(
        sk: &rsa::RsaPrivateKey,
        hash: HashAlg,
        alg: spki::AlgorithmIdentifierOwned,
        pss_salt: Option<usize>,
        msg: &[u8],
    ) -> Vec<u8> {
        build_cms_token(msg, "2026-10-15T09:00:00.000Z", hash, alg, &|tbs| {
            sign_rsa(sk, hash, pss_salt, tbs)
        })
    }

    #[test]
    fn synthetic_rsa_profiles_verify_and_reject_tampering() {
        let (sk, spki) = rsa_key(2048, 1);
        let msg = b"checkpoint";
        for hash in [HashAlg::Sha256, HashAlg::Sha384, HashAlg::Sha512] {
            let pkcs_oid = match hash {
                HashAlg::Sha256 => ID_SHA256_RSA,
                HashAlg::Sha384 => ID_SHA384_RSA,
                HashAlg::Sha512 => ID_SHA512_RSA,
            };
            // named-hash PKCS#1 v1.5, bare rsaEncryption, and PSS (salt = hash length and 20)
            let cases = [
                (
                    spki::AlgorithmIdentifierOwned {
                        oid: pkcs_oid,
                        parameters: None,
                    },
                    None,
                ),
                (
                    spki::AlgorithmIdentifierOwned {
                        oid: ID_RSA_ENCRYPTION,
                        parameters: None,
                    },
                    None,
                ),
                (pss_alg(hash, 32), Some(32)),
                (pss_alg(hash, 20), Some(20)),
            ];
            for (alg, salt) in cases {
                let tok = rsa_token(&sk, hash, alg.clone(), salt, msg);
                assert_eq!(
                    verify_binding(&tok, &spki, msg).as_deref(),
                    Ok("2026-10-15T09:00:00.000Z"),
                    "{hash:?} {:?} {salt:?}",
                    alg.oid
                );
                assert_eq!(
                    verify_binding(&tok, &spki, b"x"),
                    Err(Rfc3161Error::ImprintMismatch)
                );
                let (_, other) = rsa_key(2048, 2);
                assert_eq!(
                    verify_token(&tok, &other),
                    Err(Rfc3161Error::SignatureInvalid)
                );
            }
        }
    }

    #[test]
    fn rsa_pss_params_that_disagree_with_the_digest_are_unsupported() {
        let (sk, spki) = rsa_key(2048, 1);
        // signed with SHA-256 digest, but the PSS parameters name SHA-512
        let tok = rsa_token(
            &sk,
            HashAlg::Sha256,
            pss_alg(HashAlg::Sha512, 32),
            Some(32),
            b"m",
        );
        assert_eq!(
            verify_token(&tok, &spki),
            Err(Rfc3161Error::UnsupportedSigAlg)
        );
        // MGF1 over a different hash than the PSS hash and the digest
        let tok = rsa_token(
            &sk,
            HashAlg::Sha256,
            pss_alg_with(HashAlg::Sha256, HashAlg::Sha512, 32),
            Some(32),
            b"m",
        );
        assert_eq!(
            verify_token(&tok, &spki),
            Err(Rfc3161Error::UnsupportedSigAlg)
        );
        // PKCS#1 OID naming SHA-384 with a SHA-256 digest
        let alg = spki::AlgorithmIdentifierOwned {
            oid: ID_SHA384_RSA,
            parameters: None,
        };
        let tok = rsa_token(&sk, HashAlg::Sha256, alg, None, b"m");
        assert_eq!(
            verify_token(&tok, &spki),
            Err(Rfc3161Error::UnsupportedSigAlg)
        );
        // PSS with a wrong salt length for the signature fails the signature, not the parser
        let tok = rsa_token(
            &sk,
            HashAlg::Sha256,
            pss_alg(HashAlg::Sha256, 32),
            Some(20),
            b"m",
        );
        assert_eq!(
            verify_token(&tok, &spki),
            Err(Rfc3161Error::SignatureInvalid)
        );
    }

    #[test]
    fn rsa_keys_under_2048_bits_are_refused() {
        let (sk, spki) = rsa_key(1024, 3);
        let alg = spki::AlgorithmIdentifierOwned {
            oid: ID_SHA256_RSA,
            parameters: None,
        };
        let tok = rsa_token(&sk, HashAlg::Sha256, alg, None, b"m");
        assert_eq!(
            verify_token(&tok, &spki),
            Err(Rfc3161Error::UnsupportedSigAlg)
        );
    }

    #[test]
    fn unknown_signature_algorithms_are_refused() {
        // ecdsa-with-SHA384 and an RSA OID of a hash we do not accept both fail closed
        let sk = rsa_key(2048, 1).0;
        let alg = spki::AlgorithmIdentifierOwned {
            oid: ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.3"),
            parameters: None,
        };
        let tok = rsa_token(&sk, HashAlg::Sha384, alg, None, b"m");
        let spki = rsa_key(2048, 1).1;
        assert_eq!(
            verify_token(&tok, &spki),
            Err(Rfc3161Error::UnsupportedSigAlg)
        );
    }

    // ---------------------------------------------------------------------------------------------
    // ECDSA known-answer tests (KATs). They use only hex constants and averin's own private verifiers,
    // no p256/p384/ecdsa API, so they run unchanged on any RustCrypto line. Keys are the RFC 6979
    // Appendix A.2.5 / A.2.6 private keys. The signatures are RFC 6979 deterministic signatures,
    // generated with an independent stdlib-only Python implementation (cross-checked against the RFC
    // 6979 published r values for P-256/SHA-256 "sample" and P-384/SHA-384 "sample"). The high-S forms
    // are (r, n - s). The P-256 profile hash is SHA-256, the P-384 profile hash is SHA-512; the
    // CONFUSED signatures are valid under SHA-512 (P-256) and SHA-384 (P-384) and must be rejected.
    const P256_N: &str = "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551";
    const P256_PUB: &str = "60fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb67903fe1008b8bc99a41ae9e95628bc64f2f1b20c2d7e9f5177a3c294d4462299";
    const P256_SAMPLE: (&str, &str) = (
        "efd48b2aacb6a8fd1140dd9cd45e81d69d2c877b56aaf991c34d0ea84eaf3716",
        "f7cb1c942d657c41d436c7a1b6e29f65f3e900dbb9aff4064dc4ab2f843acda8",
    );
    const P256_SAMPLE_HIGH_S: (&str, &str) = (
        "efd48b2aacb6a8fd1140dd9cd45e81d69d2c877b56aaf991c34d0ea84eaf3716",
        "0834e36ad29a83bf2bc9385e491d6099c8fdf9d1ed67aa7ea5f51f93782857a9",
    );
    const P256_TEST: (&str, &str) = (
        "f1abb023518351cd71d881567b1ea663ed3efcf6c5132b354f28d3b0b7d38367",
        "019f4113742a2b14bd25926b49c649155f267e60d3814b4c0cc84250e46f0083",
    );
    const P256_CONFUSED: (&str, &str) = (
        "8496a60b5e9b47c825488827e0495b0e3fa109ec4568fd3f8d1097678eb97f00",
        "2362ab1adbe2b8adf9cb9edab740ea6049c028114f2460f96554f61fae3302fe",
    );
    const P384_N: &str = "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973";
    const P384_PUB: &str = "ec3a4e415b4e19a4568618029f427fa5da9a8bc4ae92e02e06aae5286b300c64def8f0ea9055866064a254515480bc138015d9b72d7d57244ea8ef9ac0c621896708a59367f9dfb9f54ca84b3f1c9db1288b231c3ae0d4fe7344fd2533264720";
    const P384_SAMPLE: (&str, &str) = ("ed0959d5880ab2d869ae7f6c2915c6d60f96507f9cb3e047c0046861da4a799cfe30f35cc900056d7c99cd7882433709", "512c8cceee3890a84058ce1e22dbc2198f42323ce8aca9135329f03c068e5112dc7cc3ef3446defceb01a45c2667fdd5");
    const P384_SAMPLE_HIGH_S: (&str, &str) = ("ed0959d5880ab2d869ae7f6c2915c6d60f96507f9cb3e047c0046861da4a799cfe30f35cc900056d7c99cd7882433709", "aed3733111c76f57bfa731e1dd243de670bdcdc3175356ec74395d45eda8dccc7b9d49c31469c87e01ea750ea65d2b9e");
    const P384_TEST: (&str, &str) = ("a0d5d090c9980faf3c2ce57b7ae951d31977dd11c775d314af55f76c676447d06fb6495cd21b4b6e340fc236584fb277", "976984e59b4c77b0e8e4460dca3d9f20e07b9bb1f63beefaf576f6b2e8b224634a2092cd3792e0159ad9cee37659c736");
    const P384_CONFUSED: (&str, &str) = ("94edbb92a5ecb8aad4736e56c691916b3f88140666ce9fa73d64c4ea95ad133c81a648152e44acf96e36dd1e80fabe46", "99ef4aeb15f178cea1fe40db2603138f130e740a19624526203b6351d0a3a94fa329c145786e679e7b82c71a38628ac8");

    const P256_ALG: &[u8] = &[
        0x30, 0x13, 0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01, 0x06, 0x08, 0x2A, 0x86,
        0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07,
    ];
    const P384_ALG: &[u8] = &[
        0x30, 0x10, 0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01, 0x06, 0x05, 0x2B, 0x81,
        0x04, 0x00, 0x22,
    ];

    fn unhex(s: &str) -> Vec<u8> {
        assert!(s.len() & 1 == 0);
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    fn tlv(tag: u8, body: &[u8]) -> Vec<u8> {
        let mut v = vec![tag];
        if body.len() < 128 {
            v.push(body.len() as u8);
        } else {
            v.push(0x81);
            v.push(body.len() as u8);
        }
        v.extend_from_slice(body);
        v
    }

    /// Minimal DER INTEGER for a non-negative big-endian value.
    fn int_min(v: &[u8]) -> Vec<u8> {
        let mut i = 0;
        while i + 1 < v.len() && v[i] == 0 {
            i += 1;
        }
        let mut b = v[i..].to_vec();
        if b[0] & 0x80 != 0 {
            b.insert(0, 0);
        }
        tlv(0x02, &b)
    }

    fn seq_of(parts: &[Vec<u8>]) -> Vec<u8> {
        tlv(0x30, &parts.concat())
    }

    fn sig_der(r: &[u8], s: &[u8]) -> Vec<u8> {
        seq_of(&[int_min(r), int_min(s)])
    }

    fn spki_of(alg: &[u8], unused: u8, point: &[u8]) -> Vec<u8> {
        let mut bits = vec![unused];
        bits.extend_from_slice(point);
        seq_of(&[alg.to_vec(), tlv(0x03, &bits)])
    }

    fn uncompressed(pub_hex: &str) -> Vec<u8> {
        let mut p = vec![0x04];
        p.extend(unhex(pub_hex));
        p
    }

    fn compressed(pub_hex: &str) -> Vec<u8> {
        let xy = unhex(pub_hex);
        let l = xy.len() / 2;
        let mut p = vec![if xy[xy.len() - 1] & 1 == 1 {
            0x03
        } else {
            0x02
        }];
        p.extend_from_slice(&xy[..l]);
        p
    }

    type VerifyFn = fn(&[u8], &[u8], &[u8]) -> Result<(), Rfc3161Error>;

    struct Curve {
        verify: VerifyFn,
        other: VerifyFn,
        alg: &'static [u8],
        other_alg: &'static [u8],
        n: &'static str,
        pubk: &'static str,
        sample: (&'static str, &'static str),
        test: (&'static str, &'static str),
        high_s: (&'static str, &'static str),
        confused: (&'static str, &'static str),
        scalar_len: usize,
    }

    fn curves() -> [Curve; 2] {
        [
            Curve {
                verify: verify_ecdsa_p256,
                other: verify_ecdsa_p384,
                alg: P256_ALG,
                other_alg: P384_ALG,
                n: P256_N,
                pubk: P256_PUB,
                sample: P256_SAMPLE,
                test: P256_TEST,
                high_s: P256_SAMPLE_HIGH_S,
                confused: P256_CONFUSED,
                scalar_len: 32,
            },
            Curve {
                verify: verify_ecdsa_p384,
                other: verify_ecdsa_p256,
                alg: P384_ALG,
                other_alg: P256_ALG,
                n: P384_N,
                pubk: P384_PUB,
                sample: P384_SAMPLE,
                test: P384_TEST,
                high_s: P384_SAMPLE_HIGH_S,
                confused: P384_CONFUSED,
                scalar_len: 48,
            },
        ]
    }

    fn pair(p: (&str, &str)) -> (Vec<u8>, Vec<u8>) {
        (unhex(p.0), unhex(p.1))
    }

    #[test]
    fn ecdsa_kat_accepts() {
        for c in curves() {
            let spki = spki_of(c.alg, 0, &uncompressed(c.pubk));
            // K1, K2, K3: sample, test, and the high-S form (accepted, as before the migration).
            for (m, p) in [
                (&b"sample"[..], c.sample),
                (&b"test"[..], c.test),
                (&b"sample"[..], c.high_s),
            ] {
                let (r, s) = pair(p);
                assert_eq!((c.verify)(&spki, m, &sig_der(&r, &s)), Ok(()));
            }
            // K4: compressed SEC1 point.
            let spki_c = spki_of(c.alg, 0, &compressed(c.pubk));
            let (r, s) = pair(c.sample);
            assert_eq!((c.verify)(&spki_c, b"sample", &sig_der(&r, &s)), Ok(()));
        }
    }

    #[test]
    fn ecdsa_kat_rejects_bad_signatures() {
        let bad = Err(Rfc3161Error::SignatureInvalid);
        for c in curves() {
            let spki = spki_of(c.alg, 0, &uncompressed(c.pubk));
            let v = |m: &[u8], sig: &[u8]| (c.verify)(&spki, m, sig);
            let (r, s) = pair(c.sample);
            let good = sig_der(&r, &s);
            let l = c.scalar_len;
            let n = unhex(c.n);
            let mut n_minus_1 = n.clone();
            *n_minus_1.last_mut().unwrap() -= 1;
            assert!(n_minus_1[0] & 0x80 != 0);

            assert_eq!(v(b"sample", &good), Ok(())); // control
            assert_eq!(v(b"test", &good), bad); // K5 wrong message
            let (cr, cs) = pair(c.confused);
            assert_eq!(v(b"sample", &sig_der(&cr, &cs)), bad); // K6 digest confusion
            assert_eq!(v(b"sample", &sig_der(&s, &r)), bad); // K7 swapped
            let zero = vec![0u8; l];
            assert_eq!(v(b"sample", &sig_der(&zero, &s)), bad); // K8 r = 0
            assert_eq!(v(b"sample", &sig_der(&r, &zero)), bad); // K8 s = 0
            assert_eq!(v(b"sample", &sig_der(&n, &s)), bad); // K9 r = n
            assert_eq!(v(b"sample", &sig_der(&r, &n)), bad); // K9 s = n

            // K10: superfluous leading zero in an INTEGER.
            let mut r_pad = vec![0u8];
            r_pad.extend_from_slice(&int_min(&r)[2..]);
            let padded = seq_of(&[tlv(0x02, &r_pad), int_min(&s)]);
            assert_eq!(v(b"sample", &padded), bad);
            // K11: negative INTEGER (n - 1 has its top bit set; no 0x00 guard byte).
            let neg = seq_of(&[tlv(0x02, &n_minus_1), int_min(&s)]);
            assert_eq!(v(b"sample", &neg), bad);
            // K12: long-form SEQUENCE length where the short form is required.
            let body = good[2..].to_vec();
            let mut longform = vec![0x30, 0x81, body.len() as u8];
            longform.extend_from_slice(&body);
            assert_eq!(v(b"sample", &longform), bad);
            // K13: trailing byte after the SEQUENCE.
            let mut trail = good.clone();
            trail.push(0x00);
            assert_eq!(v(b"sample", &trail), bad);
            // K14: wrong outer tag (SET).
            let mut set = good.clone();
            set[0] = 0x31;
            assert_eq!(v(b"sample", &set), bad);
            // K15: raw r || s (P1363) instead of DER.
            let mut p1363 = r.clone();
            p1363.extend_from_slice(&s);
            assert_eq!(v(b"sample", &p1363), bad);
            // K16: empty, one byte, 1000 bytes of garbage (no panic).
            assert_eq!(v(b"sample", &[]), bad);
            assert_eq!(v(b"sample", &[0x30]), bad);
            assert_eq!(v(b"sample", &[0xA5; 1000]), bad);
            // K17: over-long (l + 1 byte) non-zero scalar.
            let mut long_s = vec![0x01];
            long_s.extend_from_slice(&s);
            assert_eq!(
                v(b"sample", &seq_of(&[int_min(&r), tlv(0x02, &long_s)])),
                bad
            );
            // K18: zero-length INTEGER.
            assert_eq!(v(b"sample", &seq_of(&[tlv(0x02, &[]), int_min(&s)])), bad);
            // Truncated signature.
            assert_eq!(v(b"sample", &good[..good.len() - 1]), bad);
        }
    }

    #[test]
    fn ecdsa_kat_rejects_bad_keys() {
        for c in curves() {
            let (r, s) = pair(c.sample);
            let sig = sig_der(&r, &s);
            let good_pt = uncompressed(c.pubk);
            let unsupported = Err(Rfc3161Error::UnsupportedSigAlg);
            // K19: the other curve's key with this curve's verifier, and the reverse.
            let other_pt = {
                let o = curves();
                let oc = if c.scalar_len == 32 { &o[1] } else { &o[0] };
                uncompressed(oc.pubk)
            };
            assert_eq!(
                (c.verify)(&spki_of(c.other_alg, 0, &other_pt), b"sample", &sig),
                unsupported
            );
            // This curve's key under the other curve's verifier.
            assert_eq!(
                (c.other)(&spki_of(c.alg, 0, &good_pt), b"sample", &sig),
                unsupported
            );
            // K20: identity point.
            assert_eq!(
                (c.verify)(&spki_of(c.alg, 0, &[0x00]), b"sample", &sig),
                unsupported
            );
            // K21: off-curve point (last byte of Y changed).
            let mut off = good_pt.clone();
            *off.last_mut().unwrap() ^= 0x01;
            assert_eq!(
                (c.verify)(&spki_of(c.alg, 0, &off), b"sample", &sig),
                unsupported
            );
            // K22: BIT STRING with a non-zero unused-bits count.
            assert_eq!(
                (c.verify)(&spki_of(c.alg, 1, &good_pt), b"sample", &sig),
                unsupported
            );
            // K23: hybrid point tags.
            for tag in [0x06u8, 0x07] {
                let mut hy = good_pt.clone();
                hy[0] = tag;
                assert_eq!(
                    (c.verify)(&spki_of(c.alg, 0, &hy), b"sample", &sig),
                    unsupported
                );
            }
            // Wrong-length point.
            let short = &good_pt[..good_pt.len() - 1];
            assert_eq!(
                (c.verify)(&spki_of(c.alg, 0, short), b"sample", &sig),
                unsupported
            );
            // K24: truncated SPKI is a DER error.
            let spki = spki_of(c.alg, 0, &good_pt);
            assert!(matches!(
                (c.verify)(&spki[..spki.len() - 3], b"sample", &sig),
                Err(Rfc3161Error::Der(_))
            ));
        }
    }
}
