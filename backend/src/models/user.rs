use serde::{Serialize, Deserialize};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct User {
    pub user_id: i64,
    pub username: String,
    pub password: String,
    pub administrator: bool,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Claims {
    pub sub: String, // username
    pub admin: bool,
    pub exp: u64, // epoch in seconds
}
