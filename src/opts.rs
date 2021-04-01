use std::path::PathBuf;
pub use structopt::StructOpt;

#[derive(StructOpt)]
pub enum Opts {
    #[structopt()]
    /// Generate a certificate
    Generate(GenerateOpts),

    #[structopt()]
    /// Create a detached signature for a document using a private key and a certificate
    Sign(SignOpts),

    #[structopt()]
    /// Validate authenticy and integrity of a signed file
    Check(CheckOpts),
}

#[derive(StructOpt)]
pub struct GenerateOpts {
    #[structopt(long)]
    /// Credentials that will apear on the certificate, e.g., "Bob bob@example.com"
    pub credentials: String,

    #[structopt(parse(from_os_str), long = "pubkey")]
    /// File containing the public key (in OpenSSH format) that will apear on the certificate
    pub pubkey_path: PathBuf,

    #[structopt(parse(from_os_str), long = "privkey")]
    /// File containing the private key (in OpenSSH format) that will sign the certificate
    pub privkey_path: PathBuf,

    #[structopt(long)]
    /// Private key passphrase
    pub passphrase: Option<String>,

    #[structopt(parse(from_os_str), long = "certificate")]
    /// Issuer certificate file (must match private key used), leave empty if generating a self-signed certificate
    pub certificate_path: Option<PathBuf>,

    #[structopt(parse(from_os_str), long = "output")]
    /// Name to the generated certificate file
    pub output_path: PathBuf,
}

#[derive(StructOpt)]
pub struct SignOpts {
    #[structopt(parse(from_os_str), long = "document")]
    /// Document file to be signed
    pub document_path: PathBuf,

    #[structopt(parse(from_os_str), long = "certificate")]
    /// Certificate file   
    pub certificate_path: PathBuf,

    #[structopt(parse(from_os_str), long = "privkey")]
    /// File containing the private key (in OpenSSH format) that will sign the document
    pub privkey_path: PathBuf,

    #[structopt(long)]
    /// Private key passphrase
    pub passphrase: Option<String>,
}

#[derive(StructOpt)]
pub struct CheckOpts {
    #[structopt(parse(from_os_str), long = "document")]
    /// Document file to be checked 
    pub document_path: PathBuf,

    #[structopt(parse(from_os_str), long = "trust")]
    /// Folder containing trusted certificates
    pub trust_path: PathBuf,
}
