use df_share::*;
use err_mac::create_err_with_impls;
use error::Unspecified;
use pki_types::pem::PemObject;
use pki_types::{CertificateDer, ServerName};
use rustls::{ClientConfig, ClientConnection, RootCertStore, StreamOwned};
use std::io;
use std::net::TcpStream;
use std::sync::Arc;
use std::{fs, net::ToSocketAddrs};
use ureq::{self, Agent, ReadWrite, TlsConnector, Transport};

pub struct HotCheeseAgent {
    agent: Agent,
    base: String,
}
impl HotCheeseAgent {
    pub fn new(base: impl ToString) -> Self {
        let cert_bytes = include_bytes!("../src/ssl-cert.pem");
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
            .get(format!("{}{}{}", self.base, "/generate/", name).as_str())
            .call()?;
        Ok(res.into_string().unwrap_or_default())
    }
    pub fn read(&self, name: &str) -> Result<Vec<u8>, HotAgentErr> {
        let client = EphemeralClient::new()?;
        let (to_send, decryptor) = client.sendable();
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
    // let res = agent.generate("test3").unwrap();
    // println!("{}", res);
    let res = agent.read("test3").unwrap();
    println!("{}", to_hex_str(&res));
}
