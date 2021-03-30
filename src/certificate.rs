use serde::{Deserialize, Serialize};
use std::io::Write;

#[derive(Serialize, Deserialize)]
pub struct Certificate {
    pub subject_credentials: String,
    pub public_key: String,
    pub issuer_credentials: Option<String>, //None if self-signed
    pub signature: Option<String>,
}

impl Certificate {
    pub fn from_toml_string(string: &String) -> Result<Certificate, toml::de::Error> {
        toml::from_str(&string)
    }

    pub fn to_toml_string(&self) -> String {
        toml::to_string(self).unwrap()
    }

    pub fn get_signable_part_as_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        match &self.issuer_credentials {
            Some(issuer_credentials) => write!(
                &mut buf,
                "{}{}{}",
                self.subject_credentials, self.public_key, issuer_credentials
            )
            .unwrap(),
            None => write!(&mut buf, "{}{}", self.subject_credentials, self.public_key).unwrap(),
        }
        buf
    }
}
