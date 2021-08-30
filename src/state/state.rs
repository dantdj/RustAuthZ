use crate::key_providers::{ AsyncKeyProvider, GoogleKeyProvider};

pub struct AppState {
    provider: GoogleKeyProvider,
}