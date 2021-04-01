mod certificate;
mod opts;
mod signature;

use base64;
use certificate::Certificate;
use opts::{CheckOpts, GenerateOpts, Opts, SignOpts};
use osshkeys::{KeyPair, PrivateParts, PublicKey, PublicParts};
use signature::DetachedSignature;
use std::fs::{self, File};
use std::io::prelude::*;
use std::path::PathBuf;
use structopt::StructOpt;

const CERTIFICATE_EXT: &str = "certficicate";
const DETACHED_SIGNATURE_EXT: &str = "signature";

fn main() {
    match Opts::from_args() {
        Opts::Generate(opts) => generate(opts),
        Opts::Sign(opts) => sign(opts),
        Opts::Check(opts) => check(opts),
    }
}

fn generate(opts: GenerateOpts) {
    let public_key = read_to_pubkey(&opts.pubkey_path);

    let issuer_credentials = match opts.certificate_path {
        Some(certificate_file) => read_to_certificate(&certificate_file).issuer_credentials,
        None => None,
    };

    let mut certificate = Certificate {
        subject_credentials: opts.credentials,
        public_key: public_key.to_string(),
        issuer_credentials,
        signature: None,
    };

    let private_key = read_to_privkey(&opts.privkey_path, &opts.passphrase);

    let signature = private_key
        .sign(&certificate.get_signable_part_as_bytes())
        .unwrap_or_else(|error| panic!("Error signing certificate: {}", error));

    let signature = base64::encode(signature);
    certificate.signature = Some(signature);

    let mut output_file = opts.output_path;
    output_file.set_extension(CERTIFICATE_EXT);

    create_file_and_write(&output_file, &certificate.to_toml_string().as_bytes());
}

fn sign(opts: SignOpts) {
    let content = read_to_string(&opts.document_path);

    let keypair = read_to_privkey(&opts.privkey_path, &opts.passphrase);

    let certificate = read_to_certificate(&opts.certificate_path);

    let encrypted_digest = keypair
        .sign(&content.as_bytes())
        .unwrap_or_else(|error| panic!("Error signing document: {}", error));

    let detached_signature = DetachedSignature {
        signature: base64::encode(&encrypted_digest),
        signatory_credentials: certificate.subject_credentials,
    };

    let mut detached_signature_path = opts.document_path.clone();
    detached_signature_path.set_extension(DETACHED_SIGNATURE_EXT);

    create_file_and_write(
        &detached_signature_path,
        &detached_signature.to_toml_string().as_bytes(),
    );
}

fn check(opts: CheckOpts) {
    let content = read_to_string(&opts.document_path);

    let mut detached_signature_path = opts.document_path.clone();
    detached_signature_path.set_extension(DETACHED_SIGNATURE_EXT);

    let detached_signature = read_to_detached_signature(&detached_signature_path);

    let certificate = find_certificate(&opts.trust_path, detached_signature.signatory_credentials);

    match certificate {
        Some(certificate) => {
            let signature = base64::decode(detached_signature.signature).unwrap_or_else(|error| {
                panic!(
                    "Error decoding signature {}: {}",
                    detached_signature_path.display(),
                    error
                )
            });

            let public_key =
                PublicKey::from_keystr(&certificate.public_key).unwrap_or_else(|error| {
                    panic!("Error reading public key from found certificate: {}", error)
                });

            let pass = public_key
                .verify(content.as_bytes(), &signature)
                .unwrap_or_else(|error| panic!("Error validating signature: {}", error));

            if pass {
                println!("The document is authentic");
            } else {
                println!("The document is compromised");
            }
        }
        None => println!("No trusted certificate with given credentials found"),
    };
}

fn find_certificate(folder: &PathBuf, credentials: String) -> Option<Certificate> {
    let paths = fs::read_dir(&folder)
        .unwrap_or_else(|error| {
            panic!(
                "Error opening trusted certificates location {}: {}",
                folder.display(),
                error
            )
        })
        .filter_map(|p| p.ok());

    let certificates_paths = paths.filter(|p| match p.path().extension() {
        Some(extension) => (extension == CERTIFICATE_EXT),
        None => false,
    });

    certificates_paths
        .filter_map(|p| fs::read_to_string(&p.path()).ok())
        .filter_map(|c| Certificate::from_toml_string(&c).ok())
        .find(|c| c.subject_credentials == credentials)
}

fn read_to_string(path: &PathBuf) -> String {
    fs::read_to_string(path)
        .unwrap_or_else(|error| panic!("Error reading file {}: {}", path.display(), error))
}

fn read_to_privkey(path: &PathBuf, passphrase: &Option<String>) -> KeyPair {
    let privkey_string = read_to_string(&path);
    match passphrase {
        Some(passphrase) => KeyPair::from_keystr(&privkey_string, Some(&passphrase)),
        None => KeyPair::from_keystr(&privkey_string, None),
    }
    .unwrap_or_else(|error| {
        panic!(
            "Error reading private key from file {}: {}",
            path.display(),
            error
        )
    })
}

fn read_to_pubkey(path: &PathBuf) -> PublicKey {
    let pubkey_string = read_to_string(&path);
    PublicKey::from_keystr(&pubkey_string).unwrap_or_else(|error| {
        panic!(
            "Error reading public key from file {}: {}",
            path.display(),
            error
        )
    })
}

fn read_to_certificate(path: &PathBuf) -> Certificate {
    let certificate = read_to_string(&path);
    Certificate::from_toml_string(&certificate).unwrap_or_else(|error| {
        panic!(
            "Error reading certificate from file {}: {}",
            path.display(),
            error
        )
    })
}

fn read_to_detached_signature(path: &PathBuf) -> DetachedSignature {
    let detached_signature_str = read_to_string(&path);
    DetachedSignature::from_toml_string(&detached_signature_str).unwrap_or_else(|error| {
        panic!(
            "Error reading detached signature from file {}: {}",
            path.display(),
            error
        )
    })
}

fn create_file_and_write(path: &PathBuf, content: &[u8]) {
    let mut output = File::create(&path)
        .unwrap_or_else(|error| panic!("Error creating file {}: {}", path.display(), error));

    output
        .write(content)
        .unwrap_or_else(|error| panic!("Error writing on file {}: {}", path.display(), error));
}
