use anyhow::{Context, Result};
use passkeep::PasswordGenerator;

fn main() -> Result<()> {
    pretty_env_logger::init();

    let password = PasswordGenerator::new()
        .with_lowercase_chars()
        .with_uppercase_chars()
        .with_symbols()
        .with_numbers()
        .with_length(20)
        .generate()
        .context("unable to generate password")?;
    println!("Generated Password: {}", password);

    Ok(())
}
