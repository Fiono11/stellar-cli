use super::{deploy, id, threshold_sign};

#[derive(Debug, clap::Subcommand)]
pub enum Cmd {
    /// Get Id of builtin Soroban Asset Contract. Deprecated, use `soroban contract id asset` instead
    Id(id::asset::Cmd),
    /// Deploy builtin Soroban Asset Contract
    Deploy(deploy::asset::Cmd),
    /// Threshold sign builtin Soroban Asset Contract
    ThresholdSign(threshold_sign::asset::Cmd),
}

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error(transparent)]
    Id(#[from] id::asset::Error),
    #[error(transparent)]
    Deploy(#[from] deploy::asset::Error),
    #[error(transparent)]
    ThresholdSign(#[from] threshold_sign::asset::Error),
}

impl Cmd {
    pub async fn run(&self) -> Result<(), Error> {
        match &self {
            Cmd::Id(id) => id.run()?,
            Cmd::Deploy(asset) => asset.run().await?,
            Cmd::ThresholdSign(asset) => asset.run().await?,
        }
        Ok(())
    }
}
