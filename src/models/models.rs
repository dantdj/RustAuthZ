use jsonwebtoken::TokenData;

pub struct Token<T> {
    pub valid: bool,
    pub token_data: TokenData<T>,
}
