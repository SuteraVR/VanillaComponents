use std::fmt::{Debug, Display};

use tracing_error::SpanTrace;

pub trait TraceableError {
    fn trace(&self) -> &SpanTrace;
}

pub struct CapturedError<E: std::error::Error> {
    pub error: E,
    span_trace: SpanTrace,
}

impl<E: std::error::Error> TraceableError for CapturedError<E> {
    fn trace(&self) -> &SpanTrace {
        &self.span_trace
    }
}

impl<E: std::error::Error> Display for CapturedError<E> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        <E as Display>::fmt(&self.error, f)
    }
}

impl<E: std::error::Error + Debug> Debug for CapturedError<E> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        <E as Debug>::fmt(&self.error, f)
    }
}

impl<E: std::error::Error + PartialEq> PartialEq for CapturedError<E> {
    fn eq(&self, other: &Self) -> bool {
        self.error == other.error
    }
}

impl<E: std::error::Error + Eq> Eq for CapturedError<E> {}

impl<E: std::error::Error> std::error::Error for CapturedError<E> {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.error.source()
    }
}

impl<E: std::error::Error> From<E> for CapturedError<E> {
    fn from(error: E) -> Self {
        Self {
            error,
            span_trace: SpanTrace::capture(),
        }
    }
}
