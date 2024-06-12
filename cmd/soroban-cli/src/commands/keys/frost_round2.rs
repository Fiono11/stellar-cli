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
    AccountId, Asset, ContractDataDurability, ContractExecutable, ContractIdPreimage,
    CreateContractArgs, HashIdPreimage, HashIdPreimageSorobanAuthorization, HostFunction,
    InvokeHostFunctionOp, LedgerKey::ContractData, LedgerKeyContractData, Limits, Memo,
    MuxedAccount, Operation, OperationBody, PaymentOp, Preconditions, PublicKey, ScAddress, ScVal,
    SequenceNumber, SorobanAddressCredentials, SorobanAuthorizationEntry, SorobanCredentials,
    Transaction, TransactionExt, TransactionSignaturePayload,
    TransactionSignaturePayloadTaggedTransaction, Uint256, VecM, WriteXdr,
};
use std::{
    fs::{self, File},
    io::Write,
    path::PathBuf,
    str::FromStr,
};

use crate::{
    commands::config,
    fee::add_padding_to_instructions,
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

        println!("rpc: {:?}", network.rpc_url);

        let pk = stellar_strkey::ed25519::PublicKey::from_string(&config.source_account).unwrap();

        //client
        //.verify_network_passphrase(Some(&network.network_passphrase))
        //.await?;
        //let key = config.key_pair().unwrap();
        //let key = SigningKey::from_bytes(&signing_share.secret_key);

        // Get the account sequence number
        //let public_strkey =
        //stellar_strkey::ed25519::PublicKey(key.verifying_key().to_bytes()).to_string();
        // TODO: use symbols for the method names (both here and in serve)

        let account_details = client.get_account(&pk.to_string()).await.unwrap();
        let sequence: i64 = account_details.seq_num.into();
        let network_passphrase = &network.network_passphrase;

        /*let contract_id = contract_id_hash_from_asset(&asset, network_passphrase).unwrap();
        let contract = ScAddress::Contract(contract_id.clone());
        let mut read_write = vec![
            ContractData(LedgerKeyContractData {
                contract: contract.clone(),
                key: ScVal::LedgerKeyContractInstance,
                durability: ContractDataDurability::Persistent,
            }),
            ContractData(LedgerKeyContractData {
                contract: contract.clone(),
                key: ScVal::Vec(Some(
                    vec![ScVal::Symbol("Metadata".try_into().unwrap())]
                        .try_into()
                        .unwrap(),
                )),
                durability: ContractDataDurability::Persistent,
            }),
        ];
        if asset != Asset::Native {
            read_write.push(ContractData(LedgerKeyContractData {
                contract,
                key: ScVal::Vec(Some(
                    vec![ScVal::Symbol("Admin".try_into().unwrap())]
                        .try_into()
                        .unwrap(),
                )),
                durability: ContractDataDurability::Persistent,
            }));
            }*/

        let op = Operation {
            source_account: None,
            body: OperationBody::Payment(PaymentOp {
                destination: MuxedAccount::Ed25519(Uint256(pk.0)),
                asset: Asset::Native,
                amount: 100,
            }),
        };

        //println!("sequence: {:?}", sequence);

        let tx = Transaction {
            source_account: MuxedAccount::Ed25519(Uint256(pk.0)),
            fee: 100,
            seq_num: SequenceNumber(sequence + 1),
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

        //let mut tx = txn.transaction().clone();
        //let Some(mut op) = requires_auth(&tx) else {
        //return Ok(None);
        //};

        /*let Operation {
            body: OperationBody::InvokeHostFunction(ref mut body),
            ..
        } = op
        else {
            return Ok(());
        };

        let network_id = Hash(Sha256::digest(network_passphrase.as_bytes()).into());

        //let verification_key = source_key.verifying_key();
        let verification_key = pk;
        let source_address = verification_key.0;

        /*let signed_auths = body
        .auth
        .as_slice()
        .iter()
        .map(|raw_auth| {
            let mut auth = raw_auth.clone();
            let SorobanAuthorizationEntry {
                credentials: SorobanCredentials::Address(ref mut credentials),
                ..
            } = auth
            else {
                // Doesn't need special signing
                return Ok(auth);
            };
            let SorobanAddressCredentials { ref address, .. } = credentials;

            // See if we have a signer for this authorizationEntry
            // If not, then we Error
            let needle = match address {
                ScAddress::Account(AccountId(PublicKey::PublicKeyTypeEd25519(Uint256(
                    ref a,
                )))) => a,
                ScAddress::Contract(Hash(c)) => {
                    // This address is for a contract. This means we're using a custom
                    // smart-contract account. Currently the CLI doesn't support that yet.
                    //return Err(Error::MissingSignerForAddress {
                    //address: stellar_strkey::Strkey::Contract(stellar_strkey::Contract(*c))
                    //.to_string(),
                    //});
                    return Err(Error::E);
                }
            };
            let signer = if let Some(s) = signers
                .iter()
                .find(|s| needle == s.verifying_key().as_bytes())
            {
                s
            } else if needle == source_address {
                // This is the source address, so we can sign it
                source_key
            } else {
                // We don't have a signer for this address
                return Err(Error::MissingSignerForAddress {
                    address: stellar_strkey::Strkey::PublicKeyEd25519(
                        stellar_strkey::ed25519::PublicKey(*needle),
                    )
                    .to_string(),
                });
            };

            sign_soroban_authorization_entry(
                raw_auth,
                signer,
                signature_expiration_ledger,
                &network_id,
            )
        })
        .collect::<Result<Vec<_>, Error>>()?;*/

        let signature_expiration_ledger = txn.sim_response().latest_ledger + 60;

        let mut auth = body.auth[0].clone();
        let SorobanAuthorizationEntry {
            credentials: SorobanCredentials::Address(ref mut credentials),
            ..
        } = auth
        else {
            // Doesn't need special signing
            return Ok(());
        };
        let SorobanAddressCredentials { nonce, .. } = credentials;

        let preimage = HashIdPreimage::SorobanAuthorization(HashIdPreimageSorobanAuthorization {
            network_id: network_id.clone(),
            invocation: auth.root_invocation.clone(),
            nonce: *nonce,
            signature_expiration_ledger,
        })
        .to_xdr(Limits::none())
        .unwrap();

        let payload = Sha256::digest(preimage);
        let signature = signer.sign(&payload);

        let map = ScMap::sorted_from(vec![
            (
                ScVal::Symbol(ScSymbol("public_key".try_into()?)),
                ScVal::Bytes(
                    signer
                        .verifying_key()
                        .to_bytes()
                        .to_vec()
                        .try_into()
                        .map_err(Error::Xdr)?,
                ),
            ),
            (
                ScVal::Symbol(ScSymbol("signature".try_into()?)),
                ScVal::Bytes(
                    signature
                        .to_bytes()
                        .to_vec()
                        .try_into()
                        .map_err(Error::Xdr)?,
                ),
            ),
        ])
        .map_err(Error::Xdr)?;
        credentials.signature = ScVal::Vec(Some(
            vec![ScVal::Map(Some(map))].try_into().map_err(Error::Xdr)?,
        ));
        credentials.signature_expiration_ledger = signature_expiration_ledger;
        auth.credentials = SorobanCredentials::Address(credentials.clone());

        body.auth = auth.try_into()?;
        tx.operations = vec![op].try_into()?;*/

        let signature_payload = TransactionSignaturePayload {
            network_id: Hash(Sha256::digest(network_passphrase).into()),
            tagged_transaction: TransactionSignaturePayloadTaggedTransaction::Tx(tx.clone()),
        };

        let hash: [u8; 32] =
            Sha256::digest(signature_payload.to_xdr(Limits::none()).unwrap()).into();

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
