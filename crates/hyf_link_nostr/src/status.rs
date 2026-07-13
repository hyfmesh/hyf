#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NostrRelayStatusPrefix {
    Duplicate,
    Pow,
    Blocked,
    RateLimited,
    Invalid,
    Restricted,
    Mute,
    Error,
    AuthRequired,
    Unknown,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NostrRelayStatus<'a> {
    pub prefix: NostrRelayStatusPrefix,
    pub raw_prefix: &'a str,
    pub detail: &'a str,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NostrPublishOutcome<'a> {
    Accepted { message: &'a str },
    AcceptedDuplicate { status: NostrRelayStatus<'a> },
    Rejected { status: NostrRelayStatus<'a> },
}

pub fn parse_relay_status(message: &str) -> NostrRelayStatus<'_> {
    let Some((prefix, detail)) = message.split_once(':') else {
        return NostrRelayStatus {
            prefix: NostrRelayStatusPrefix::Unknown,
            raw_prefix: "",
            detail: message,
        };
    };

    NostrRelayStatus {
        prefix: status_prefix(prefix),
        raw_prefix: prefix,
        detail: detail.strip_prefix(' ').unwrap_or(detail),
    }
}

pub fn classify_ok_message(accepted: bool, message: &str) -> NostrPublishOutcome<'_> {
    let status = parse_relay_status(message);
    if accepted {
        if status.prefix == NostrRelayStatusPrefix::Duplicate {
            NostrPublishOutcome::AcceptedDuplicate { status }
        } else {
            NostrPublishOutcome::Accepted { message }
        }
    } else {
        NostrPublishOutcome::Rejected { status }
    }
}

pub fn classify_closed_message(message: &str) -> NostrRelayStatus<'_> {
    parse_relay_status(message)
}

const fn status_prefix(prefix: &str) -> NostrRelayStatusPrefix {
    match prefix.as_bytes() {
        b"duplicate" => NostrRelayStatusPrefix::Duplicate,
        b"pow" => NostrRelayStatusPrefix::Pow,
        b"blocked" => NostrRelayStatusPrefix::Blocked,
        b"rate-limited" => NostrRelayStatusPrefix::RateLimited,
        b"invalid" => NostrRelayStatusPrefix::Invalid,
        b"restricted" => NostrRelayStatusPrefix::Restricted,
        b"mute" => NostrRelayStatusPrefix::Mute,
        b"error" => NostrRelayStatusPrefix::Error,
        b"auth-required" => NostrRelayStatusPrefix::AuthRequired,
        _ => NostrRelayStatusPrefix::Unknown,
    }
}

#[cfg(test)]
mod tests {
    use super::{
        NostrPublishOutcome, NostrRelayStatus, NostrRelayStatusPrefix, classify_closed_message,
        classify_ok_message, parse_relay_status,
    };

    #[test]
    fn relay_status_parses_all_known_prefixes() {
        let cases = [
            (
                "duplicate: already stored",
                NostrRelayStatusPrefix::Duplicate,
            ),
            ("pow: need work", NostrRelayStatusPrefix::Pow),
            ("blocked: policy", NostrRelayStatusPrefix::Blocked),
            (
                "rate-limited: slow down",
                NostrRelayStatusPrefix::RateLimited,
            ),
            ("invalid: bad event", NostrRelayStatusPrefix::Invalid),
            (
                "restricted: write denied",
                NostrRelayStatusPrefix::Restricted,
            ),
            ("mute: ignored", NostrRelayStatusPrefix::Mute),
            ("error: relay failed", NostrRelayStatusPrefix::Error),
            (
                "auth-required: challenge first",
                NostrRelayStatusPrefix::AuthRequired,
            ),
        ];

        for (message, prefix) in cases {
            let status = parse_relay_status(message);
            assert_eq!(status.prefix, prefix);
            assert!(!status.detail.is_empty());
        }
    }

    #[test]
    fn relay_status_surfaces_unknown_prefixes_and_missing_prefix() {
        assert_eq!(
            parse_relay_status("custom-prefix: something happened"),
            NostrRelayStatus {
                prefix: NostrRelayStatusPrefix::Unknown,
                raw_prefix: "custom-prefix",
                detail: "something happened",
            }
        );
        assert_eq!(
            parse_relay_status("plain relay text"),
            NostrRelayStatus {
                prefix: NostrRelayStatusPrefix::Unknown,
                raw_prefix: "",
                detail: "plain relay text",
            }
        );
    }

    #[test]
    fn ok_status_classifies_duplicate_accepts_separately() {
        assert_eq!(
            classify_ok_message(true, "duplicate: already stored"),
            NostrPublishOutcome::AcceptedDuplicate {
                status: NostrRelayStatus {
                    prefix: NostrRelayStatusPrefix::Duplicate,
                    raw_prefix: "duplicate",
                    detail: "already stored",
                }
            }
        );
        assert_eq!(
            classify_ok_message(true, ""),
            NostrPublishOutcome::Accepted { message: "" }
        );
        assert_eq!(
            classify_ok_message(false, "blocked: policy"),
            NostrPublishOutcome::Rejected {
                status: NostrRelayStatus {
                    prefix: NostrRelayStatusPrefix::Blocked,
                    raw_prefix: "blocked",
                    detail: "policy",
                }
            }
        );
    }

    #[test]
    fn closed_status_uses_same_prefix_mapping() {
        assert_eq!(
            classify_closed_message("auth-required: challenge first"),
            NostrRelayStatus {
                prefix: NostrRelayStatusPrefix::AuthRequired,
                raw_prefix: "auth-required",
                detail: "challenge first",
            }
        );
    }
}
