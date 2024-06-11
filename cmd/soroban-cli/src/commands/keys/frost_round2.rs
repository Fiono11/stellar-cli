use olaf::{
    frost::{SigningCommitments, SigningNonces},
    simplpedpop::SPPOutput,
    SigningKeypair,
};
use serde_json::from_str;
use sha2::{Digest, Sha256};
use soroban_env_host::xdr::Hash;
use soroban_rpc::Client;
use soroban_sdk::xdr::{
    ContractExecutable, ContractIdPreimage, CreateContractArgs, HostFunction, InvokeHostFunctionOp,
    Limits, Memo, MuxedAccount, Operation, OperationBody, Preconditions, SequenceNumber,
    Transaction, TransactionExt, TransactionSignaturePayload,
    TransactionSignaturePayloadTaggedTransaction, Uint256, VecM, WriteXdr,
};
use std::{
    fs::{self, File},
    io::Write,
    path::PathBuf,
    str::FromStr,
};

use crate::{commands::config, fee::add_padding_to_instructions, utils::parsing::parse_asset};

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error(transparent)]
    StrKey(#[from] stellar_strkey::DecodeError),
}

#[derive(Debug, clap::Parser, Clone)]
#[group(skip)]
pub struct Cmd {
    /// ID of the Stellar classic asset to wrap, e.g. "USDC:G...5"
    #[arg(long)]
    pub asset: String,
    #[command(flatten)]
    pub config: config::Args,
    //#[command(flatten)]
    //pub fee: crate::fee::Args,
    // The folder that contains the files for the round 2 of the FROST protocol
    //pub files: String,
}

impl Cmd {
    pub async fn run(&self) -> Result<(), Error> {
        let file_path: std::path::PathBuf =
            PathBuf::from_str("/Users/ruimorais/stellar-cli/cmd/soroban-cli/src/commands/keys")
                .unwrap();

        let signing_commitments_string =
            fs::read_to_string(file_path.join("signing_commitments.json")).unwrap();

        let signing_commitments_bytes: Vec<Vec<u8>> =
            from_str(&signing_commitments_string).unwrap();

        let signing_commitments: Vec<SigningCommitments> = signing_commitments_bytes
            .iter()
            .map(|signing_commitments| SigningCommitments::from_bytes(signing_commitments).unwrap())
            .collect();

        let signing_nonces_string =
            fs::read_to_string(file_path.join("signing_nonces.json")).unwrap();

        let signing_nonces_bytes: Vec<u8> = from_str(&signing_nonces_string).unwrap();
        let signing_nonces = SigningNonces::from_bytes(&signing_nonces_bytes).unwrap();

        let signing_share_string =
            fs::read_to_string(file_path.join("signing_share.json")).unwrap();

        let signing_share_vec: Vec<u8> = from_str(&signing_share_string).unwrap();

        let mut signing_share_bytes = [0; 64];
        signing_share_bytes.copy_from_slice(&signing_share_vec);

        let signing_share = SigningKeypair::from_bytes(&signing_share_bytes).unwrap();

        let output_string = fs::read_to_string(file_path.join("spp_output.json")).unwrap();

        let output_bytes: Vec<u8> = from_str(&output_string).unwrap();
        let spp_output = SPPOutput::from_bytes(&output_bytes).unwrap();

        let config = &self.config;
        // Parse asset
        let asset = parse_asset(&self.asset).unwrap();

        let network = config.get_network().unwrap();
        let client = Client::new(&network.rpc_url).unwrap();
        //client
        //.verify_network_passphrase(Some(&network.network_passphrase))
        //.await?;
        //let key = config.key_pair().unwrap();
        //let key = SigningKey::from_bytes(&signing_share.secret_key);

        // Get the account sequence number
        //let public_strkey =
        //stellar_strkey::ed25519::PublicKey(key.verifying_key().to_bytes()).to_string();
        // TODO: use symbols for the method names (both here and in serve)
        //let account_details = client.get_account(&public_strkey).await.unwrap();
        //let sequence: i64 = account_details.seq_num.into();
        let network_passphrase = &network.network_passphrase;
        //let contract_id = contract_id_hash_from_asset(&asset, network_passphrase).unwrap();

        let op = Operation {
            source_account: None,
            body: OperationBody::InvokeHostFunction(InvokeHostFunctionOp {
                host_function: HostFunction::CreateContract(CreateContractArgs {
                    contract_id_preimage: ContractIdPreimage::Asset(asset.clone()),
                    executable: ContractExecutable::StellarAsset,
                }),
                auth: VecM::default(),
            }),
        };

        let pk = stellar_strkey::ed25519::PublicKey::from_string(&config.source_account).unwrap();

        let tx = Transaction {
            source_account: MuxedAccount::Ed25519(Uint256(pk.0)),
            fee: 1,
            seq_num: SequenceNumber(0),
            cond: Preconditions::None,
            memo: Memo::None,
            operations: vec![op].try_into().unwrap(),
            ext: TransactionExt::V0,
        };

        //let tx = build_wrap_token_tx(&asset, &contract_id, 0, 1, network_passphrase, &key).unwrap();
        //if self.fee.build_only {
        //return Ok(TxnResult::Txn(tx));
        //}
        //let txn1 = client.create_assembled_transaction(&tx).await.unwrap();
        //let txn = self.fee.apply_to_assembled_txn(txn);
        //let txn = add_padding_to_instructions(txn1);

        let signature_payload = TransactionSignaturePayload {
            network_id: Hash(Sha256::digest(network_passphrase).into()),
            tagged_transaction: TransactionSignaturePayloadTaggedTransaction::Tx(tx.clone()),
        };
        let mut hash = [0; 32];
        hash = Sha256::digest(signature_payload.to_xdr(Limits::none()).unwrap()).into();

        println!("hash: {:?}", hash);

        let signing_package = signing_share
            .sign(
                //&txn.hash(network_passphrase).unwrap(),
                &hash,
                &spp_output,
                &signing_commitments,
                &signing_nonces,
            )
            .unwrap();

        let signing_packages_vec = vec![signing_package.to_bytes()];

        let signing_package_json = serde_json::to_string_pretty(&signing_packages_vec).unwrap();

        let mut signing_package_file =
            File::create(file_path.join("signing_packages.json")).unwrap();

        signing_package_file
            .write_all(signing_package_json.as_bytes())
            .unwrap();

        Ok(())
    }
}
