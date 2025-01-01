use std::fmt::{Debug, Display};

use tracing_error::SpanTrace;

pub trait TraceableError: std::error::Error {
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

pub trait ResultTracingUnwrapExt<T, E: TraceableError> {
    fn tracing_unwrap(self) -> T;
}

pub trait ResultCaptureErrExt<T, U: std::error::Error> {
    fn capture_err(self) -> Result<T, CapturedError<U>>;
}

impl<T, E: TraceableError> ResultTracingUnwrapExt<T, E> for Result<T, E> {
    #[inline(always)]
    fn tracing_unwrap(self) -> T {
        match self {
            Ok(value) => value,
            Err(ref error) => {
                tracing::error!(error = %error, "called `unwrap()` on an `Err` Value");
                eprintln!("== TRACING ==");
                eprintln!("{}", error.trace());
                self.unwrap();
                unreachable!()
            }
        }
    }
}

impl<T, U: std::error::Error> ResultCaptureErrExt<T, U> for Result<T, U> {
    #[inline(always)]
    fn capture_err(self) -> Result<T, CapturedError<U>> {
        self.map_err(|error| CapturedError {
            error,
            span_trace: SpanTrace::capture(),
        })
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
