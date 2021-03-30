use std::path::PathBuf;
pub use structopt::StructOpt;

#[derive(StructOpt)]
pub enum Opts {
    #[structopt()]
    /// Genereta a certificate
    Generate(GenerateOpts),

    #[structopt()]
    /// Create a detached signature for a document using a private key and a certificate
    Sign(SignOpts),

    #[structopt()]
    /// Verify integrity of a signed file
    Check(CheckOpts),
}

#[derive(StructOpt)]
pub struct GenerateOpts {
    #[structopt(long)]
    /// Credentials that will apear on the certificate, e.g., "Bob bob@example.com"
    pub credentials: String,

    #[structopt(parse(from_os_str), long)]
    /// File containing the public key (in OpenSSH format) that will apear on the certificate
    pub pubkey: PathBuf,

    #[structopt(parse(from_os_str), long)]
    /// File containing the private key (in OpenSSH format) that will sign the certificate
    pub privkey: PathBuf,

    #[structopt(long)]
    /// Private key passphrase
    pub passphrase: Option<String>,

    #[structopt(parse(from_os_str), long)]
    /// Certificate file from the issuer (must match used private key) leave empty if generating a self-signed certificate
    pub certificate: Option<PathBuf>,

    #[structopt(parse(from_os_str), long)]
    /// Name to the generated certificate file  
    pub output: PathBuf,
}

#[derive(StructOpt)]
pub struct SignOpts {
    #[structopt(parse(from_os_str), long)]
    /// Document file to be signed
    pub document: PathBuf,

    #[structopt(parse(from_os_str), long)]
    /// Certificate file   
    pub certificate: PathBuf,

    #[structopt(parse(from_os_str), long)]
    /// File containing the private key (in OpenSSH format) that will sign the document
    pub privkey: PathBuf,

    #[structopt(long)]
    /// Private key passphrase
    pub passphrase: Option<String>,
}

#[derive(StructOpt)]
pub struct CheckOpts {
    #[structopt(parse(from_os_str), long)]
    /// Document file to be checked
    pub document: PathBuf,

    #[structopt(parse(from_os_str), long)]
    /// Folder containing trusted certificates
    pub trust: PathBuf,
}
