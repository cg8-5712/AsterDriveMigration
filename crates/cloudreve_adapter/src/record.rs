#[derive(Debug, Clone)]
pub struct CloudreveStoragePolicyRecord {
    pub policy: cloudreve_schema::storage_policies::Model,
    pub local_root: Option<String>,
}

#[derive(Debug, Clone)]
pub struct CloudrevePolicyGroupRecord {
    pub group: cloudreve_schema::groups::Model,
}

#[derive(Debug, Clone)]
pub struct CloudreveUserRecord {
    pub user: cloudreve_schema::users::Model,
    pub group: Option<cloudreve_schema::groups::Model>,
    pub username: String,
}

#[derive(Debug, Clone)]
pub struct CloudreveFolderRecord {
    pub folder: cloudreve_schema::files::Model,
}
