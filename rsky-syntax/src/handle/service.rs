//! The rules for a handle under a domain of the PDS itself (a service domain, such as
//! `alice.example.com` on a PDS that serves `.example.com`). A PDS applies them when it creates an
//! account or changes a handle. An app in front of that PDS can check a handle with the same rules
//! before it asks the PDS.

use super::reserved::RESERVED_SUBDOMAINS;
use super::slurs::has_explicit_slur;
use thiserror::Error;

/// Why a handle under a service domain is refused.
#[derive(Error, Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServiceHandleError {
    #[error("Invalid domain")]
    Domain,
    #[error("Invalid characters in handle")]
    Dots,
    #[error("Handle too short")]
    TooShort,
    #[error("Handle too long")]
    TooLong,
    #[error("Inappropriate language in handle")]
    Slur,
    #[error("Reserved handle")]
    Reserved,
}

/// The domain as a suffix with its leading dot, so that a sibling domain
/// (`evilpds.example.com` against `pds.example.com`) never matches.
fn as_dotted_suffix(domain: &str) -> String {
    if domain.starts_with('.') {
        domain.to_string()
    } else {
        format!(".{domain}")
    }
}

/// Whether the handle is under one of the service domains.
pub fn is_service_domain(handle: &str, domains: &[String]) -> bool {
    domains
        .iter()
        .any(|domain| handle.ends_with(as_dotted_suffix(domain).as_str()))
}

/// Checks a normalized handle (see [`super::normalize_and_ensure_valid_handle`]) against the rules
/// for a handle under one of `domains`: one label of 3 to 18 characters, no slur, and not a
/// reserved name unless `allow_reserved`.
pub fn ensure_service_handle(
    handle: &str,
    domains: &[String],
    allow_reserved: bool,
) -> Result<(), ServiceHandleError> {
    let suffix = domains
        .iter()
        .map(|domain| as_dotted_suffix(domain))
        .find(|domain| handle.ends_with(domain.as_str()))
        .ok_or(ServiceHandleError::Domain)?;
    let front = &handle[..handle.len() - suffix.len()];
    if front.contains('.') {
        return Err(ServiceHandleError::Dots);
    }
    if front.len() < 3 {
        return Err(ServiceHandleError::TooShort);
    }
    if front.len() > 18 {
        return Err(ServiceHandleError::TooLong);
    }
    if has_explicit_slur(handle) {
        return Err(ServiceHandleError::Slur);
    }
    if !allow_reserved && RESERVED_SUBDOMAINS.contains(front) {
        return Err(ServiceHandleError::Reserved);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::ServiceHandleError::*;
    use super::*;

    fn check(handle: &str) -> Result<(), ServiceHandleError> {
        ensure_service_handle(handle, &[".example.com".to_string()], false)
    }

    #[test]
    fn each_rule_of_a_service_handle() {
        assert_eq!(check("alice.example.com"), Ok(()));
        assert_eq!(check("alice.evilexample.com"), Err(Domain));
        assert_eq!(check("alice.other.org"), Err(Domain));
        assert_eq!(check("a.b.example.com"), Err(Dots));
        assert_eq!(check("al.example.com"), Err(TooShort));
        assert_eq!(check("abcdefghijklmnopqrs.example.com"), Err(TooLong));
        assert_eq!(check("help.example.com"), Err(Reserved));
        assert_eq!(
            ensure_service_handle("help.example.com", &["example.com".to_string()], true),
            Ok(())
        );
    }

    #[test]
    fn a_service_domain_matches_only_at_a_label() {
        let domains = ["pds.example.com".to_string()];
        assert!(is_service_domain("alice.pds.example.com", &domains));
        assert!(!is_service_domain("alice.evilpds.example.com", &domains));
    }
}
