//! Source adapter contracts that do not depend on either database schema.

#[derive(Debug, Clone, Copy, Default)]
pub struct ConversionContext;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SkipReason {
    pub code: &'static str,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Conversion<T> {
    Ready(T),
    Skipped(SkipReason),
}

impl<T> Conversion<T> {
    #[must_use]
    pub fn into_ready(self) -> Option<T> {
        match self {
            Self::Ready(value) => Some(value),
            Self::Skipped(_) => None,
        }
    }
}

pub trait SourceConverter<Source> {
    type Output;
    type Error;

    fn convert(
        &self,
        source: Source,
        context: &ConversionContext,
    ) -> Result<Conversion<Self::Output>, Self::Error>;
}
