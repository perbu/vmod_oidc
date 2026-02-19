use rand::Rng;
use rand::distr::Alphanumeric;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use url::Url;

pub(crate) const MAX_RETURN_TO_LEN: usize = 2048;
pub(crate) const MAX_CLAIMS_BYTES: usize = 3072;

pub(crate) fn cookie_value<'a>(cookie_header: Option<&'a str>, cookie_name: &str) -> Option<&'a str> {
    cookie_header.and_then(|cookie_header| {
        cookie_header.split(';').find_map(|part| {
            let (name, value) = part.trim().split_once('=')?;
            if name == cookie_name {
                Some(value)
            } else {
                None
            }
        })
    })
}

pub(crate) fn query_param(url_or_path: &str, key: &str) -> Option<String> {
    let parsed = parse_url_or_path(url_or_path)?;
    parsed
        .query_pairs()
        .find_map(|(k, v)| if k == key { Some(v.to_string()) } else { None })
}

fn parse_url_or_path(url_or_path: &str) -> Option<Url> {
    if let Ok(url) = Url::parse(url_or_path) {
        return Some(url);
    }

    let normalized = if url_or_path.starts_with('/') {
        format!("http://localhost{url_or_path}")
    } else {
        format!("http://localhost/{url_or_path}")
    };

    Url::parse(&normalized).ok()
}

pub(crate) fn derive_return_to(current_request_url: &str) -> String {
    let without_fragment = current_request_url
        .split_once('#')
        .map(|(head, _)| head)
        .unwrap_or(current_request_url);

    let candidate = if let Ok(url) = Url::parse(without_fragment) {
        let mut value = url.path().to_string();
        if let Some(query) = url.query() {
            value.push('?');
            value.push_str(query);
        }
        value
    } else {
        without_fragment.to_string()
    };

    validate_return_to(&candidate)
}

pub(crate) fn validate_return_to(input: &str) -> String {
    let no_fragment = input
        .split_once('#')
        .map(|(head, _)| head)
        .unwrap_or(input)
        .trim();

    if no_fragment.is_empty() {
        return "/".to_string();
    }

    if !no_fragment.starts_with('/') || no_fragment.starts_with("//") {
        return "/".to_string();
    }

    if no_fragment.contains("://") || no_fragment.len() > MAX_RETURN_TO_LEN {
        return "/".to_string();
    }

    no_fragment.to_string()
}

pub(crate) fn random_token(len: usize) -> String {
    rand::rng()
        .sample_iter(Alphanumeric)
        .take(len)
        .map(char::from)
        .collect()
}

pub(crate) fn build_set_cookie(name: &str, value: &str, max_age_secs: u64, secure: bool) -> String {
    let mut out = format!("{name}={value}; Path=/; HttpOnly; SameSite=Lax; Max-Age={max_age_secs}");
    if secure {
        out.push_str("; Secure");
    }
    out
}

pub(crate) fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_else(|_| Duration::from_secs(0))
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn return_to_rules_are_enforced() {
        assert_eq!(derive_return_to("/protected?a=1#frag"), "/protected?a=1");
        assert_eq!(derive_return_to("https://example.test/p?q=1#x"), "/p?q=1");
        assert_eq!(validate_return_to(""), "/");
        assert_eq!(validate_return_to("http://evil.test"), "/");
        assert_eq!(validate_return_to("//evil"), "/");

        let huge = format!("/{}", "a".repeat(MAX_RETURN_TO_LEN + 1));
        assert_eq!(validate_return_to(&huge), "/");
    }
}
