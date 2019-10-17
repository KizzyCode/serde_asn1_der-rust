#![cfg(feature = "more_types")]

use oid::prelude::*;
use serde::{Deserialize, Serialize};
use serde_asn1_der::asn1_wrapper::ObjectIdentifierAsn1;

/****************************************************************************
 * https://tools.ietf.org/html/rfc2560#section-4.1.1
 *
 * OCSPRequest     ::=     SEQUENCE {
 *     tbsRequest                  TBSRequest,
 *     optionalSignature   [0]     EXPLICIT Signature OPTIONAL }
 *
 * TBSRequest      ::=     SEQUENCE {
 *     version             [0]     EXPLICIT Version DEFAULT v1,
 *     requestorName       [1]     EXPLICIT GeneralName OPTIONAL,
 *     requestList                 SEQUENCE OF Request,
 *     requestExtensions   [2]     EXPLICIT Extensions OPTIONAL }
 *
 * Signature       ::=     SEQUENCE {
 *     signatureAlgorithm      AlgorithmIdentifier,
 *     signature               BIT STRING,
 *     certs               [0] EXPLICIT SEQUENCE OF Certificate OPTIONAL }
 *
 * Version         ::=     INTEGER  {  v1(0) }
 *
 * Request         ::=     SEQUENCE {
 *     reqCert                     CertID,
 *     singleRequestExtensions     [0] EXPLICIT Extensions OPTIONAL }
 *
 * CertID          ::=     SEQUENCE {
 *     hashAlgorithm       AlgorithmIdentifier,
 *     issuerNameHash      OCTET STRING, -- Hash of Issuer's DN
 *     issuerKeyHash       OCTET STRING, -- Hash of Issuers public key
 *     serialNumber        CertificateSerialNumber }
 */

/*
 * https://tools.ietf.org/html/rfc5280#section-4.1.1.2
 *
 * AlgorithmIdentifier  ::=  SEQUENCE  {
 *      algorithm               OBJECT IDENTIFIER,
 *      parameters              ANY DEFINED BY algorithm OPTIONAL }
 ****************************************************************************/
// https://access.redhat.com/documentation/en-us/red_hat_certificate_system/9/html/administration_guide/online_certificate_status_protocol_responder
// https://lapo.it/asn1js/#MEIwQDA-MDwwOjAJBgUrDgMCGgUABBT4cyABkyiCIhU4JpmIBewdDnn8ZgQUbyBZ44kgy35o7xW5BMzM8FTvyTwCAQE

#[derive(Serialize, Deserialize, Debug, PartialEq)]
struct OCSPRequest {
    tbs_request: TBSRequest,
}

#[derive(Serialize, Deserialize, Debug, PartialEq)]
struct TBSRequest {
    request_list: Vec<Request>,
}

#[derive(Serialize, Deserialize, Debug, PartialEq)]
struct Request {
    req_cert: CertID,
}

#[derive(Serialize, Deserialize, Debug, PartialEq)]
struct CertID {
    algorithm: AlgorithmIdentifier,
    #[serde(with = "serde_bytes")]
    issuer_name_hash: Vec<u8>,
    #[serde(with = "serde_bytes")]
    issuer_key_hash: Vec<u8>,
    serial_number: u32,
}

#[derive(Serialize, Deserialize, Debug, PartialEq)]
struct AlgorithmIdentifier {
    algorithm: ObjectIdentifierAsn1,
    parameters: (),
}

#[test]
fn ocsp_request() {
    let encoded_ocsp_request = base64::decode(
        "MEIwQDA+MDwwOjAJBgUrDgMCGgUABBT4cyABkyiCIhU4J\
         pmIBewdDnn8ZgQUbyBZ44kgy35o7xW5BMzM8FTvyTwCAQE=",
    )
    .expect("invalid base64");

    let sha1_oid = ObjectIdentifier::try_from("1.3.14.3.2.26").unwrap();
    let ocsp_request = OCSPRequest {
        tbs_request: TBSRequest {
            request_list: vec![Request {
                req_cert: CertID {
                    algorithm: AlgorithmIdentifier {
                        algorithm: sha1_oid.into(),
                        parameters: (),
                    },
                    issuer_name_hash: vec![
                        0xf8, 0x73, 0x20, 0x01, 0x93, 0x28, 0x82, 0x22, 0x15, 0x38, 0x26, 0x99,
                        0x88, 0x05, 0xec, 0x1d, 0x0e, 0x79, 0xfc, 0x66,
                    ],
                    issuer_key_hash: vec![
                        0x6f, 0x20, 0x59, 0xe3, 0x89, 0x20, 0xcb, 0x7e, 0x68, 0xef, 0x15, 0xb9,
                        0x04, 0xcc, 0xcc, 0xf0, 0x54, 0xef, 0xc9, 0x3c,
                    ],
                    serial_number: 1,
                },
            }],
        },
    };

    let serialized = serde_asn1_der::to_vec(&ocsp_request).expect("failed serialization");
    assert_eq!(serialized, encoded_ocsp_request);

    let deserialized: OCSPRequest =
        serde_asn1_der::from_bytes(&encoded_ocsp_request).expect("failed deserialization");
    assert_eq!(deserialized, ocsp_request);
}
