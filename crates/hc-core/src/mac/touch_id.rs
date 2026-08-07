use crate::mac::local_auth::LaContext;

/// Prompt for Touch ID and return whether it succeeded. Thin `bool` adapter over
/// [`LaContext::evaluate_biometric`]; still used by `migrate` and the software-enclave demo.
pub fn authorize_with_touch_id(reason: &str) -> bool {
    LaContext::evaluate_biometric(reason).is_ok()
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    #[ignore = "interactive: triggers a real Touch ID prompt; run manually with `cargo test -- --ignored`"]
    fn test_touch_id() {
        println!("{}", authorize_with_touch_id("test"));
    }
}
