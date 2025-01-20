use crate::server::BackendImpl;
use get_password::get_password_from_keychain;
use touch_id::authorize_with_touch_id;

mod get_password;
mod touch_id;

pub struct MacBackend {
    service: String,
    account: String,
    store: String,
}
impl MacBackend {
    pub fn new(service: &str, account: &str, store: &str) -> Self {
        Self {
            service: service.into(),
            account: account.into(),
            store: store.into(),
        }
    }
}

impl BackendImpl for MacBackend {
    fn is_device_owner(&self, reason: &str) -> bool {
        authorize_with_touch_id(reason)
    }
    fn get_encryption_key(&self) -> Option<Vec<u8>> {
        get_password_from_keychain(&self.service, &self.account).ok()
    }
    fn store(&self) -> &str {
        &self.store
    }
    fn communicate_err(&self, e: String) {
        eprintln!("{}", e)
    }
}
