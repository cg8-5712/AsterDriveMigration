//! Schema-independent migration contracts, domain values, and state rules.

pub mod conversion;
pub mod domain;
pub mod state;

pub use conversion::{Conversion, ConversionContext, SkipReason, SourceConverter};
pub use domain::*;
pub use state::{RunStatus, StageId, StagePlan, StateError};
