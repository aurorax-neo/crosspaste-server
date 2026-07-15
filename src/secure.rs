use aes::cipher::{block_padding::Pkcs7, BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use aes::Aes256;
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use cbc::{Decryptor, Encryptor};
use p256::ecdh::diffie_hellman;
use p256::ecdsa::signature::{Signer, Verifier};
use p256::ecdsa::{Signature, SigningKey, VerifyingKey};
use p256::pkcs8::{DecodePrivateKey, DecodePublicKey, EncodePrivateKey, EncodePublicKey};
use p256::{PublicKey, SecretKey};
use rand_core::OsRng;
use rand_core::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PairingRequest {
    pub sign_public_key: String,
    pub crypt_public_key: String,
    pub token: u32,
    pub timestamp: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PairingResponse {
    pub sign_public_key: String,
    pub crypt_public_key: String,
    pub timestamp: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TrustRequest {
    pub pairing_request: PairingRequest,
    pub signature: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TrustResponse {
    pub pairing_response: PairingResponse,
    pub signature: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KeyExchangeRequest {
    pub sign_public_key: String,
    pub crypt_public_key: String,
    pub timestamp: i64,
    pub signature: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KeyExchangeResponse {
    pub sign_public_key: String,
    pub crypt_public_key: String,
    pub timestamp: i64,
    pub signature: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TrustConfirmRequest {
    pub timestamp: i64,
    pub signature: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TrustConfirmResponse {
    pub timestamp: i64,
    pub signature: String,
}

#[derive(Clone)]
pub struct ServerKeys {
    sign_key: SigningKey,
    crypt_key: SecretKey,
}

impl ServerKeys {
    pub fn generate() -> Self {
        Self {
            sign_key: SigningKey::random(&mut OsRng),
            crypt_key: SecretKey::random(&mut OsRng),
        }
    }

    pub fn from_pkcs8(sign_key_der: &[u8], crypt_key_der: &[u8]) -> anyhow::Result<Self> {
        let sign_secret = SecretKey::from_pkcs8_der(sign_key_der)?;
        Ok(Self {
            sign_key: SigningKey::from(sign_secret),
            crypt_key: SecretKey::from_pkcs8_der(crypt_key_der)?,
        })
    }

    pub fn private_keys_pkcs8(&self) -> anyhow::Result<(Vec<u8>, Vec<u8>)> {
        let sign_secret = SecretKey::from_bytes(&self.sign_key.to_bytes())?;
        Ok((
            sign_secret.to_pkcs8_der()?.as_bytes().to_vec(),
            self.crypt_key.to_pkcs8_der()?.as_bytes().to_vec(),
        ))
    }

    pub fn sign_public_key_der_b64(&self) -> anyhow::Result<String> {
        let der = self.sign_key.verifying_key().to_public_key_der()?;
        Ok(B64.encode(der.as_bytes()))
    }

    pub fn crypt_public_key_der_b64(&self) -> anyhow::Result<String> {
        let public_key = self.crypt_key.public_key();
        let der = public_key.to_public_key_der()?;
        Ok(B64.encode(der.as_bytes()))
    }

    pub fn sign(&self, data: &[u8]) -> String {
        let signature: Signature = self.sign_key.sign(data);
        B64.encode(signature.to_der().as_bytes())
    }

    pub fn encrypt_for_client(
        &self,
        client_crypt_public_key_der: &[u8],
        plaintext: &[u8],
    ) -> anyhow::Result<Vec<u8>> {
        let key = self.shared_key(client_crypt_public_key_der)?;
        let mut iv = [0u8; 16];
        OsRng.fill_bytes(&mut iv);
        let mut encrypted = Encryptor::<Aes256>::new(&key.into(), &iv.into())
            .encrypt_padded_vec_mut::<Pkcs7>(plaintext);
        let mut out = iv.to_vec();
        out.append(&mut encrypted);
        Ok(out)
    }

    pub fn decrypt_from_client(
        &self,
        client_crypt_public_key_der: &[u8],
        ciphertext: &[u8],
    ) -> anyhow::Result<Vec<u8>> {
        anyhow::ensure!(ciphertext.len() >= 16, "ciphertext too short");
        let key = self.shared_key(client_crypt_public_key_der)?;
        let (iv, data) = ciphertext.split_at(16);
        Ok(Decryptor::<Aes256>::new(&key.into(), iv.into())
            .decrypt_padded_vec_mut::<Pkcs7>(data)
            .map_err(|_| anyhow::anyhow!("invalid encrypted payload padding"))?)
    }

    fn shared_key(&self, client_crypt_public_key_der: &[u8]) -> anyhow::Result<[u8; 32]> {
        let public_key = PublicKey::from_public_key_der(client_crypt_public_key_der)?;
        let secret = diffie_hellman(self.crypt_key.to_nonzero_scalar(), public_key.as_affine());
        Ok(secret.raw_secret_bytes().as_slice().try_into()?)
    }
}

pub fn verify_pairing_request(request: &TrustRequest) -> anyhow::Result<bool> {
    let public_key = verifying_key_from_b64(&request.pairing_request.sign_public_key)?;
    let sig_bytes = B64.decode(&request.signature)?;
    let signature = Signature::from_der(&sig_bytes)?;
    Ok(public_key
        .verify(
            &pairing_request_sign_data(&request.pairing_request),
            &signature,
        )
        .is_ok())
}

pub fn sign_pairing_response(keys: &ServerKeys, response: &PairingResponse) -> String {
    keys.sign(&pairing_response_sign_data(response))
}

pub fn client_crypt_public_key(request: &TrustRequest) -> anyhow::Result<Vec<u8>> {
    Ok(B64.decode(&request.pairing_request.crypt_public_key)?)
}

pub fn verify_key_exchange_request(request: &KeyExchangeRequest) -> anyhow::Result<bool> {
    let public_key = verifying_key_from_b64(&request.sign_public_key)?;
    verify_signature(
        &public_key,
        &request.signature,
        format!(
            "{}{}{}",
            request.sign_public_key, request.crypt_public_key, request.timestamp
        )
        .as_bytes(),
    )
}

pub fn build_key_exchange_response(keys: &ServerKeys) -> anyhow::Result<KeyExchangeResponse> {
    let sign_public_key = keys.sign_public_key_der_b64()?;
    let crypt_public_key = keys.crypt_public_key_der_b64()?;
    let timestamp = crate::hub::now_ms();
    let signature = keys.sign(format!("{sign_public_key}{crypt_public_key}{timestamp}").as_bytes());
    Ok(KeyExchangeResponse {
        sign_public_key,
        crypt_public_key,
        timestamp,
        signature,
    })
}

pub fn verify_trust_confirm(
    sign_public_key: &str,
    request: &TrustConfirmRequest,
) -> anyhow::Result<bool> {
    let public_key = verifying_key_from_b64(sign_public_key)?;
    verify_signature(
        &public_key,
        &request.signature,
        request.timestamp.to_string().as_bytes(),
    )
}

pub fn build_trust_confirm_response(keys: &ServerKeys) -> TrustConfirmResponse {
    let timestamp = crate::hub::now_ms();
    TrustConfirmResponse {
        timestamp,
        signature: keys.sign(timestamp.to_string().as_bytes()),
    }
}

pub fn decode_public_key_b64(encoded: &str) -> anyhow::Result<Vec<u8>> {
    Ok(B64.decode(encoded)?)
}

pub fn compute_sas(local_public_key: &[u8], remote_public_key: &[u8]) -> u32 {
    let (first, second) = if local_public_key <= remote_public_key {
        (local_public_key, remote_public_key)
    } else {
        (remote_public_key, local_public_key)
    };
    let mut hasher = Sha256::new();
    hasher.update(first);
    hasher.update(second);
    let hash = hasher.finalize();
    let value = u32::from_be_bytes(hash[..4].try_into().expect("SHA-256 prefix"));
    (value & 0x7fff_ffff) % 1_000_000
}

fn verifying_key_from_b64(encoded: &str) -> anyhow::Result<VerifyingKey> {
    let der = B64.decode(encoded)?;
    let public_key = PublicKey::from_public_key_der(&der)?;
    Ok(VerifyingKey::from(public_key))
}

fn verify_signature(
    public_key: &VerifyingKey,
    encoded_signature: &str,
    data: &[u8],
) -> anyhow::Result<bool> {
    let signature = Signature::from_der(&B64.decode(encoded_signature)?)?;
    Ok(public_key.verify(data, &signature).is_ok())
}

fn pairing_request_sign_data(request: &PairingRequest) -> Vec<u8> {
    format!(
        "{}{}{}{}",
        request.sign_public_key, request.crypt_public_key, request.token, request.timestamp
    )
    .into_bytes()
}

fn pairing_response_sign_data(response: &PairingResponse) -> Vec<u8> {
    format!(
        "{}{}{}",
        response.sign_public_key, response.crypt_public_key, response.timestamp
    )
    .into_bytes()
}
