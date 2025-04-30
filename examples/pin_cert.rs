use df_share::*;
use err_mac::create_err_with_impls;
use error::Unspecified;
use pki_types::pem::PemObject;
use pki_types::CertificateDer;
use rustls::{ClientConfig, RootCertStore};
use std::sync::Arc;
use ureq::{self, Agent};

pub struct HotCheeseAgent {
    agent: Agent,
    base: String,
}
impl HotCheeseAgent {
    pub fn new(base: impl ToString) -> Self {
        let cert_bytes = include_bytes!("../src/conf/ssl-cert.pem");
        let pinned_cert = CertificateDer::from_pem_slice(cert_bytes).unwrap();

        let mut root_store = RootCertStore::empty();
        root_store
            .add(pinned_cert)
            .expect("Failed to add pinned certificate");

        let tls_config = Arc::new(
            ClientConfig::builder()
                .with_root_certificates(root_store)
                .with_no_client_auth(),
        );

        Self {
            base: base.to_string(),
            agent: ureq::builder()
                .https_only(true)
                .tls_config(tls_config)
                .build(),
        }
    }

    pub fn health(&self) -> Result<String, HotAgentErr> {
        let res = self
            .agent
            .get(format!("{}{}", self.base, "/health").as_str())
            .call()?;
        Ok(res.into_string().unwrap_or_default())
    }
    pub fn generate(&self, name: &str) -> Result<String, HotAgentErr> {
        let res = self
            .agent
            .get(format!("{}{}{}", self.base, "/evm_generate/", name).as_str())
            .call()?;
        Ok(res.into_string().unwrap_or_default())
    }
    pub fn address(&self, name: &str) -> Result<String, HotAgentErr> {
        let res = self
            .agent
            .get(format!("{}{}{}", self.base, "/evm_address/", name).as_str())
            .call()?;
        Ok(res.into_string().unwrap_or_default())
    }
    pub fn solana_address(&self, name: &str) -> Result<String, HotAgentErr> {
        let res = self
            .agent
            .get(format!("{}{}{}", self.base, "/solana_address/", name).as_str())
            .call()?;
        Ok(res.into_string().unwrap_or_default())
    }
    pub fn read(&self, name: &str) -> Result<Vec<u8>, HotAgentErr> {
        let client = EphemeralClient::new()?;
        let (to_send, decryptor) = client.sendable();
        println!("send pubk {}", to_hex_str(&to_send.pubk));
        let res = self
            .agent
            .get(format!("{}{}{}", self.base, "/read/", name).as_str())
            .send_bytes(&serde_json::to_vec(&to_send)?)?;
        let res_str = res.into_string()?;
        println!("received {}", res_str);
        let enc_res: ServerEncryptedRes = serde_json::from_str(res_str.as_str())?;
        Ok(decryptor.decrypt(&enc_res)?)
    }
}

create_err_with_impls!(
    #[derive(Debug)]
    pub HotAgentErr,
    Ureq(ureq::Error),
    Unspecified(Unspecified),
    Serde(serde_json::Error),
    IO(std::io::Error)
    ;
);

fn main() {
    let agent = HotCheeseAgent::new("https://localhost:5555");
    let health = agent.health().unwrap();
    println!("{}", health);
    // let res = agent.generate("test4").unwrap();
    // println!("{}", res);
    let res = agent.address("CL_GNOSIS_COWSWAP0").unwrap();
    println!("{}", res);
    let res = agent.solana_address("SOLANA_TRADER").unwrap();
    println!("solana {}", res);
}
