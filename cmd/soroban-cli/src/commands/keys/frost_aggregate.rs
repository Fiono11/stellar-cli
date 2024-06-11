use olaf::frost::{aggregate, SigningPackage};
use serde_json::from_str;
use sha2::digest::generic_array::sequence;
use soroban_rpc::Client;
use soroban_sdk::xdr::{
    DecoratedSignature, Signature, SignatureHint, TransactionEnvelope, TransactionV1Envelope,
};
use std::fs;

use crate::{
    commands::{config, contract::deploy::asset::build_wrap_token_tx},
    utils::{contract_id_hash_from_asset, parsing::parse_asset},
};

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error(transparent)]
    StrKey(#[from] stellar_strkey::DecodeError),
}

#[derive(Debug, clap::Parser, Clone)]
#[group(skip)]
pub struct Cmd {
    /// The folder that contains the files for the aggregate round of the FROST protocol
    pub files: String,
    #[arg(long)]
    pub asset: String,
    #[command(flatten)]
    pub config: config::Args,
    #[command(flatten)]
    pub fee: crate::fee::Args,
}

impl Cmd {
    pub async fn run(&self) -> Result<(), Error> {
        let file_path: std::path::PathBuf = self.files.clone().into();

        let signing_packages_string =
            fs::read_to_string(file_path.join("signing_packages.json")).unwrap();
        let signing_packages_bytes: Vec<Vec<u8>> = from_str(&signing_packages_string).unwrap();

        let signing_packages: Vec<SigningPackage> = signing_packages_bytes
            .iter()
            .map(|signing_commitments| SigningPackage::from_bytes(signing_commitments).unwrap())
            .collect();

        let tx_signature = aggregate(&signing_packages).unwrap();

        let config = &self.config;
        // Parse asset
        let asset = parse_asset(&self.asset).unwrap();

        let network = config.get_network().unwrap();
        let client = Client::new(&network.rpc_url).unwrap();
        //client
        //.verify_network_passphrase(Some(&network.network_passphrase))
        //.await?;
        let key = config.key_pair().unwrap();

        // Get the account sequence number
        let public_strkey =
            stellar_strkey::ed25519::PublicKey(key.verifying_key().to_bytes()).to_string();
        // TODO: use symbols for the method names (both here and in serve)
        let account_details = client.get_account(&public_strkey).await.unwrap();
        let sequence: i64 = account_details.seq_num.into();
        let network_passphrase = &network.network_passphrase;
        let contract_id = contract_id_hash_from_asset(&asset, network_passphrase).unwrap();
        let tx = build_wrap_token_tx(
            &asset,
            &contract_id,
            sequence,
            self.fee.fee,
            network_passphrase,
            &key,
        )
        .unwrap();
        if self.fee.build_only {
            //return Ok(TxnResult::Txn(tx));
        }
        let txn = client.create_assembled_transaction(&tx).await.unwrap();
        let txn = self.fee.apply_to_assembled_txn(txn);

        let decorated_signature = DecoratedSignature {
            hint: SignatureHint(key.verifying_key().to_bytes()[28..].try_into().unwrap()),
            signature: Signature(tx_signature.to_bytes().try_into().unwrap()),
        };

        let tx = TransactionEnvelope::Tx(TransactionV1Envelope {
            tx: txn.transaction().clone(),
            signatures: vec![decorated_signature].try_into().unwrap(),
        });

        client.send_transaction(&tx).await;

        Ok(())
    }
}
