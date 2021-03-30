use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub struct DetachedSignature {
    pub signature: String,
    pub signatory_credentials: String,
}

impl DetachedSignature {
    pub fn from_toml_string(string: &String) -> Result<DetachedSignature, toml::de::Error> {
        toml::from_str(&string)
    }
    pub fn to_toml_string(&self) -> String {
        toml::to_string(self).unwrap()
    }
}
