use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use clap::{Parser, Subcommand};
use p256::{
    ecdsa::signature::{Signer, Verifier},
    ecdsa::{Signature, SigningKey, VerifyingKey},
};
use rand_core::OsRng;
use sha2::{Digest, Sha256};
use std::{
    fs,
    io::{self},
    path::PathBuf,
};
use thiserror::Error;

// custom error enum
#[derive(Error, Debug)]
pub enum SignerError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Base64 decode error: {0}")]
    Base64Decode(#[from] base64::DecodeError),
    #[error("Key error: {0}")]
    Key(String),
    #[error("Signature error: {0}")]
    Signature(String),
}

// define the CLI structure and subcommands
#[derive(Parser)]
#[clap(name = "signer", version = "1.0", author = "Your Name")]
pub struct Cli {
    #[clap(subcommand)]
    pub command: Commands,
}

// define possible subcommands for the CLI
#[derive(Subcommand)]
pub enum Commands {
    #[clap(name = "generate-keys")]
    GenerateKeys {
        #[clap(short = 'k', long, value_name = "PRIVATE_KEY")]
        private_key: PathBuf,

        #[clap(short = 'p', long, value_name = "PUBLIC_KEY")]
        public_key: PathBuf,
    },

    #[clap(name = "sign")]
    Sign {
        #[clap(short = 'i', long, value_name = "INPUT")]
        input: PathBuf,

        #[clap(short = 'k', long, value_name = "PRIVATE_KEY")]
        private_key: PathBuf,

        #[clap(short = 'o', long, value_name = "OUTPUT")]
        output: PathBuf,
    },

    #[clap(name = "verify")]
    Verify {
        #[clap(short = 'i', long, value_name = "INPUT")]
        input: PathBuf,

        #[clap(short = 'p', long, value_name = "PUBLIC_KEY")]
        public_key: PathBuf,

        #[clap(short = 's', long, value_name = "SIGNATURE")]
        signature: PathBuf,
    },
}

// component trait
trait Component {
    fn process(&mut self) -> Result<(), SignerError>;
}

// key generation component
struct KeyGenerator {
    private_key_path: PathBuf,
    public_key_path: PathBuf,
}

impl KeyGenerator {
    fn new(private_key_path: PathBuf, public_key_path: PathBuf) -> Self {
        KeyGenerator {
            private_key_path,
            public_key_path,
        }
    }
}

impl Component for KeyGenerator {
    fn process(&mut self) -> Result<(), SignerError> {
        let (signing_key, verifying_key) = generate_keypair()?;
        save_keys(
            &signing_key,
            &verifying_key,
            &self.private_key_path,
            &self.public_key_path,
        )?;
        Ok(())
    }
}

// file signing component
struct FileSigner {
    input_path: PathBuf,
    private_key_path: PathBuf,
    output_path: PathBuf,
}

impl FileSigner {
    fn new(input_path: PathBuf, private_key_path: PathBuf, output_path: PathBuf) -> Self {
        FileSigner {
            input_path,
            private_key_path,
            output_path,
        }
    }
}

impl Component for FileSigner {
    fn process(&mut self) -> Result<(), SignerError> {
        let signing_key = load_private_key(&self.private_key_path)?;
        sign_file(&self.input_path, &signing_key, &self.output_path)?;
        Ok(())
    }
}

// signature verification component
struct SignatureVerifier {
    input_path: PathBuf,
    public_key_path: PathBuf,
    signature_path: PathBuf,
}

impl SignatureVerifier {
    fn new(input_path: PathBuf, public_key_path: PathBuf, signature_path: PathBuf) -> Self {
        SignatureVerifier {
            input_path,
            public_key_path,
            signature_path,
        }
    }
}

impl Component for SignatureVerifier {
    fn process(&mut self) -> Result<(), SignerError> {
        let verifying_key = load_public_key(&self.public_key_path)?;
        let is_valid = verify_signature(&self.input_path, &verifying_key, &self.signature_path)?;
        if is_valid {
            println!("Signature is valid!");
        } else {
            println!("Signature is invalid!");
            std::process::exit(1);
        }
        Ok(())
    }
}

fn generate_keypair() -> Result<(SigningKey, VerifyingKey), SignerError> {
    let signing_key = SigningKey::random(&mut OsRng);
    let verifying_key = VerifyingKey::from(&signing_key);
    Ok((signing_key, verifying_key))
}

fn save_keys(
    private_key: &SigningKey,
    public_key: &VerifyingKey,
    private_key_path: &PathBuf,
    public_key_path: &PathBuf,
) -> Result<(), SignerError> {
    let private_key_bytes = private_key.to_bytes();
    let encoded_point = public_key.to_encoded_point(false);
    let public_key_bytes = encoded_point.as_bytes();

    fs::write(private_key_path, BASE64.encode(private_key_bytes))?;
    fs::write(public_key_path, BASE64.encode(public_key_bytes))?;

    Ok(())
}

fn load_private_key(path: &PathBuf) -> Result<SigningKey, SignerError> {
    let key_str = fs::read_to_string(path)?;
    let key_bytes = BASE64
        .decode(key_str.trim())
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    let key_bytes: [u8; 32] = key_bytes
        .try_into()
        .map_err(|_| SignerError::Key("Invalid private key length".to_string()))?;
    SigningKey::from_bytes(&key_bytes.into()).map_err(|e| SignerError::Key(e.to_string()))
}

fn load_public_key(path: &PathBuf) -> Result<VerifyingKey, SignerError> {
    let key_str = fs::read_to_string(path)?;
    let key_bytes = BASE64
        .decode(key_str.trim())
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    VerifyingKey::from_sec1_bytes(&key_bytes).map_err(|e| SignerError::Key(e.to_string()))
}

fn sign_file(
    input_path: &PathBuf,
    private_key: &SigningKey,
    signature_path: &PathBuf,
) -> Result<(), SignerError> {
    let content = fs::read(input_path)?;
    let mut hasher = Sha256::new();
    hasher.update(&content);
    let hash = hasher.finalize();

    let signature: Signature = private_key.sign(&hash);
    fs::write(signature_path, BASE64.encode(signature.to_der()))?;

    Ok(())
}

fn verify_signature(
    input_path: &PathBuf,
    public_key: &VerifyingKey,
    signature_path: &PathBuf,
) -> Result<bool, SignerError> {
    let content = fs::read(input_path)?;
    let mut hasher = Sha256::new();
    hasher.update(&content);
    let hash = hasher.finalize();

    let signature_str = fs::read_to_string(signature_path)?;
    let signature_bytes = BASE64
        .decode(signature_str.trim())
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    let signature =
        Signature::from_der(&signature_bytes).map_err(|e| SignerError::Signature(e.to_string()))?;

    Ok(public_key.verify(&hash, &signature).is_ok())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    match &cli.command {
        Commands::GenerateKeys {
            private_key,
            public_key,
        } => {
            let mut key_generator = KeyGenerator::new(private_key.clone(), public_key.clone());
            key_generator.process()?;
            println!("Keys generated successfully!");
        }
        Commands::Sign {
            input,
            private_key,
            output,
        } => {
            let mut file_signer =
                FileSigner::new(input.clone(), private_key.clone(), output.clone());
            file_signer.process()?;
            println!("File signed successfully!");
        }
        Commands::Verify {
            input,
            public_key,
            signature,
        } => {
            let mut signature_verifier =
                SignatureVerifier::new(input.clone(), public_key.clone(), signature.clone());
            signature_verifier.process()?;
        }
    }

    Ok(())
}
