#[macro_use]
extern crate log;

use std::{convert::TryFrom, num::NonZeroUsize};

use bitflags::bitflags;
use rand::prelude::*;
use thiserror::Error;

const LOWERCASE_DATA: &str = "abcdefghijklmnopqrstuvwxyz";
const UPPERCASE_DATA: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const SYMBOLS: &str = "!@#$%^&*()_+-={}[]\":;'?><,./~`|\\";
const NUMBERS: &str = "1234567890";

bitflags! {
    pub struct PasswordContents: u8 {
        const LOWERCASE = 0b00000001;
        const UPPERCASE = 0b00000010;
        const SYMBOLS   = 0b00000100;
        const NUMBERS   = 0b00001000;
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum PasswordGenerationError {
    #[error("missing possible password contents")]
    MissingContent,

    #[error("password must be more than 0 elements")]
    ZeroLengthPassword,
}

pub struct PasswordGenerator {
    contents: PasswordContents,
    length: Option<NonZeroUsize>,
}

impl PasswordGenerator {
    pub fn new() -> Self {
        Self {
            contents: PasswordContents::empty(),
            length: NonZeroUsize::new(8),
        }
    }

    pub fn with_lowercase_chars(mut self) -> Self {
        self.contents.set(PasswordContents::LOWERCASE, true);
        self
    }

    pub fn with_uppercase_chars(mut self) -> Self {
        self.contents.set(PasswordContents::UPPERCASE, true);
        self
    }

    pub fn with_symbols(mut self) -> Self {
        self.contents.set(PasswordContents::SYMBOLS, true);
        self
    }

    pub fn with_numbers(mut self) -> Self {
        self.contents.set(PasswordContents::NUMBERS, true);
        self
    }

    pub fn with_length(mut self, length: usize) -> Self {
        self.length = NonZeroUsize::try_from(length).ok();
        self
    }

    /// Generate a password
    pub fn generate(self) -> Result<String, PasswordGenerationError> {
        if self.length.is_none() {
            return Err(PasswordGenerationError::ZeroLengthPassword);
        }

        trace!("Contents: {:#?}", self.contents);
        if self.contents.is_empty() {
            return Err(PasswordGenerationError::MissingContent);
        }

        let mut rng = rand::thread_rng();

        let mut dictionary = String::new();
        if self.contents.contains(PasswordContents::LOWERCASE) {
            trace!("Adding lowercase letters to dictionary.");
            dictionary.push_str(LOWERCASE_DATA);
        }

        if self.contents.contains(PasswordContents::UPPERCASE) {
            trace!("Adding uppercase letters to dictionary.");
            dictionary.push_str(UPPERCASE_DATA);
        }

        if self.contents.contains(PasswordContents::SYMBOLS) {
            trace!("Adding symbols to dictionary.");
            dictionary.push_str(SYMBOLS);
        }

        if self.contents.contains(PasswordContents::NUMBERS) {
            trace!("Adding numbers to dictionary.");
            dictionary.push_str(NUMBERS);
        }

        let mut password = String::new();
        for _ in 0..self.length.unwrap().get() {
            password.push(dictionary.chars().choose(&mut rng).unwrap());
        }
        Ok(password)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn password_must_have_contents() {
        let result = PasswordGenerator::new().generate();

        assert_eq!(result, Err(PasswordGenerationError::MissingContent));
    }

    #[test]
    fn password_length() {
        let result = PasswordGenerator::new()
            .with_lowercase_chars()
            .with_length(43594)
            .generate();
        
        assert!(result.is_ok());

        let result = result.unwrap();
        assert_eq!(result.len(), 43594);
    }

    #[test]
    fn password_cannot_be_zero_length() {
        let result = PasswordGenerator::new()
            .with_lowercase_chars()
            .with_length(0)
            .generate();

        assert_eq!(result, Err(PasswordGenerationError::ZeroLengthPassword));
    }

    #[test]
    fn password_generator_lowercase() {
        let result = PasswordGenerator::new()
            .with_lowercase_chars()
            .with_length(1000)
            .generate();

        assert!(result.is_ok());

        let result = result.unwrap();
        assert!(result.chars().all(|c| c.is_lowercase()));
    }

    #[test]
    fn password_generator_uppercase() {
        let result = PasswordGenerator::new()
            .with_uppercase_chars()
            .with_length(1000)
            .generate();

        assert!(result.is_ok());

        let result = result.unwrap();
        assert!(result.chars().all(|c| c.is_uppercase()));
    }

    #[test]
    fn password_generator_symbols() {
        let result = PasswordGenerator::new()
            .with_symbols()
            .with_length(1000)
            .generate();

        assert!(result.is_ok());

        let result = result.unwrap();
        assert!(result.chars().all(|c| SYMBOLS.contains(c)));
    }

    #[test]
    fn password_generator_numbers() {
        let result = PasswordGenerator::new()
            .with_numbers()
            .with_length(1000)
            .generate();

        assert!(result.is_ok());

        let result = result.unwrap();
        assert!(result.chars().all(|c| c.is_numeric()));
    }
}
