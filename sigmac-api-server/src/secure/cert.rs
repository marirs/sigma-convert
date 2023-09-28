use openssl::{
    asn1::Asn1Time,
    hash::MessageDigest,
    nid::Nid,
    pkey::{PKey, Private},
    rsa::Rsa,
    x509::{X509Name, X509},
};

pub struct ResultCert {
    pub x509_certificate: X509,
    pub private_key: PKey<Private>,
}

/// Common Name
const CN: &str = "localhost";
/// Distinguished Name
const DN: &str = "localhost";
/// Subject Alternate Name
const SUB_ALT_NAME: &str = "local";
/// Country Code
const ISO_COUNTRY: &str = "US";
/// Organisation Name
const ORG_NAME: &str = "My Organisation";
/// Issuer Name/Entity
const ISSUER: &str = "My Organisation";
/// Issuer Alternate Name
const ISSUER_ALT: &str = "My Organisation";
/// SSL Validity
const VALIDITY: u32 = 30; // 30 days

pub fn generate_cert() -> ResultCert {
    //! Generates a SSL Certificate
    //!
    //! ## Example usage:
    //!
    //! ```ignore
    //! generate_cert(cert_configuration)
    //! ```
    let rsa = Rsa::generate(4096).unwrap();
    let pkey = PKey::from_rsa(rsa).unwrap();

    let mut name = X509Name::builder().unwrap();
    name.append_entry_by_nid(Nid::COMMONNAME, CN).unwrap();
    name.append_entry_by_nid(Nid::DISTINGUISHEDNAME, DN)
        .unwrap();
    name.append_entry_by_nid(Nid::SUBJECT_ALT_NAME, SUB_ALT_NAME)
        .unwrap();
    name.append_entry_by_nid(Nid::COUNTRYNAME, ISO_COUNTRY)
        .unwrap();
    name.append_entry_by_nid(Nid::ORGANIZATIONNAME, ORG_NAME)
        .unwrap();
    name.append_entry_by_nid(Nid::CERTIFICATE_ISSUER, ISSUER)
        .unwrap();
    name.append_entry_by_nid(Nid::ISSUER_ALT_NAME, ISSUER_ALT)
        .unwrap();
    let name = name.build();
    let time_before = Asn1Time::days_from_now(0).unwrap();
    let time_after = Asn1Time::days_from_now(VALIDITY).unwrap();
    let mut builder = X509::builder().unwrap();
    builder.set_version(1).unwrap();
    builder.set_subject_name(&name).unwrap();
    builder.set_issuer_name(&name).unwrap();
    builder.set_pubkey(&pkey).unwrap();
    builder.set_not_before(time_before.as_ref()).unwrap();
    builder.set_not_after(time_after.as_ref()).unwrap();
    builder.sign(&pkey, MessageDigest::sha256()).unwrap();

    let certificate: X509 = builder.build();
    ResultCert {
        x509_certificate: certificate,
        private_key: pkey,
    }
}
