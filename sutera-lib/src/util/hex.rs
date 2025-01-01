use std::fmt::Write;
use std::str::Utf8Error;
use tracing_error::SpanTrace;

use thiserror::Error;
use tracing::instrument;

use crate::error::{CapturedError, ResultCaptureErrExt, TraceableError};

#[instrument("to_hex")]
pub(crate) fn to_hex(data: &[u8]) -> String {
    data.iter().fold(String::new(), |mut acc, byte| {
        write!(acc, "{byte:02x}").unwrap();
        acc
    })
}

#[derive(Error, Debug, PartialEq, Eq)]
enum FromHexError {
    #[error(transparent)]
    Utf8(#[from] CapturedError<Utf8Error>),

    #[error(transparent)]
    ParseInt(#[from] CapturedError<std::num::ParseIntError>),
}

impl TraceableError for FromHexError {
    fn trace(&self) -> &SpanTrace {
        match self {
            FromHexError::Utf8(e) => e.trace(),
            FromHexError::ParseInt(e) => e.trace(),
        }
    }
}

#[instrument("from_hex")]
pub(crate) fn from_hex(data: &str) -> Result<Vec<u8>, FromHexError> {
    data.as_bytes()
        .chunks(2)
        .map(|chunk| {
            Ok(u8::from_str_radix(std::str::from_utf8(chunk).capture_err()?, 16).capture_err()?)
        })
        .collect::<Result<Vec<u8>, FromHexError>>()
}

#[cfg(test)]
mod tests {
    use super::*;
    use assert_matches::assert_matches;
    use pretty_assertions::assert_eq;

    #[test]
    fn from_hex_after_to_hex_should_do_nothing() {
        assert_eq!(
            from_hex(&to_hex(&[0x01, 0x02, 0x03, 0x04])),
            Ok(vec![0x01, 0x02, 0x03, 0x04])
        );
    }

    #[test]
    fn to_hex_after_from_hex_should_do_nothing() {
        assert_eq!(
            from_hex("faceb00c").map(|hex| to_hex(&hex)),
            Ok("faceb00c".to_string())
        );
    }

    #[test]
    fn from_hex_should_handle_odd_length_strings() {
        assert_eq!(from_hex("f"), Ok(vec![0xf]));
        assert_eq!(from_hex("fa"), Ok(vec![0xfa]));
        assert_eq!(from_hex("fac"), Ok(vec![0xfa, 0xc]));
        assert_eq!(from_hex("face"), Ok(vec![0xfa, 0xce]));
    }

    #[test]
    fn to_hex_should_handle_empty_input() {
        assert_eq!(to_hex(&[]), "");
    }

    #[test]
    fn from_hex_should_handle_empty_input() {
        assert_eq!(from_hex(""), Ok(vec![]));
    }

    #[test]
    fn from_hex_should_fail_for_invalid_characters() {
        assert_matches!(from_hex("g"), Err(FromHexError::ParseInt(_)));
    }
}
