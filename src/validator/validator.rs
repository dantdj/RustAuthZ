use crate::key_providers::{AsyncKeyProvider, GoogleKeyProvider};
use crate::errors::InvalidKeyError;
use crate::models::Token;
use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Validation};

#[derive(serde::Deserialize, serde::Serialize)]
pub struct Claims {
    /// The expiry time of the token
    exp: usize,
    /// The name of the individual the token was issued to
    name: String,
    /// The email of the individual the token was issued to
    email: String,
}

pub struct Validator {
    pub audience: String,
    pub issuer: String,
    key_provider: GoogleKeyProvider,
}

impl Validator {
    pub fn new(audience_value: String, issuer_value: String) -> Self {
        Self {
            audience: audience_value,
            issuer: issuer_value,
            key_provider: GoogleKeyProvider::default(),
        }
    }
    pub async fn validate_jwt(&mut self, jwt: &str) -> Result<Token<Claims>, InvalidKeyError> {
        let header = match decode_header(jwt) {
            Ok(header) => header,
            Err(e) => return Err(InvalidKeyError::new(&e.to_string())),
        };
    
        let key_to_use = match self.key_provider.get_key_async(&header.clone().kid.unwrap()).await {
            Ok(key) => key,
            Err(e) => return Err(InvalidKeyError::new(&e.details)),
        };

        let mut validation_params = Validation::new(Algorithm::RS256);
        validation_params.iss = Some(self.issuer.clone());
        validation_params.set_audience(&[self.audience.clone()]);
    
        let token_data = decode::<Claims>(
            jwt,
            &DecodingKey::from_rsa_components(&key_to_use.modulus, &key_to_use.exponent),
            &validation_params,
        );

        let token = Token {
            valid: true,
            token_data: token_data.unwrap()
        };
    
        Ok(token)
    }
}