//! Cloudreve schema records and their conversion into migration-domain values.

mod converter;
mod record;

pub use converter::CloudreveConverter;
pub use record::{
    CloudreveFolderRecord, CloudrevePolicyGroupRecord, CloudreveStoragePolicyRecord,
    CloudreveUserRecord,
};
