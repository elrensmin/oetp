// client to fetch release token from the local beacon
use oetp_core::error::{Error, Result};
use oetp_core::release::ReleaseToken;
use oetp_core::signing;
use ed25519_dalek::VerifyingKey;

pub struct BeaconClient {
    beacon_url: String,
    http_client: reqwest::Client,
    center_verifying_key: VerifyingKey,
    api_key: String,
}

impl BeaconClient {
    pub fn new(beacon_url: &str, center_public_key: &[u8; 32], api_key: &str) -> Result<Self> {
        Ok(Self {
            beacon_url: beacon_url.to_string(),
            http_client: reqwest::Client::new(),
            center_verifying_key: signing::verifying_key_from_bytes(center_public_key)?,
            api_key: api_key.to_string(),
        })
    }

    pub async fn request_token(
        &self,
        center_id: &str,
        exam_id: &str,
        device_id: &str,
    ) -> Result<ReleaseToken> {
        let resp = self
            .http_client
            .post(format!("{}/v1/beacon/token", self.beacon_url))
            .header("Content-Type", "application/json")
            .header("x-api-key", &self.api_key)
            .json(&serde_json::json!({
                "center_id": center_id,
                "exam_id": exam_id,
                "device_id": device_id,
            }))
            .send()
            .await
            .map_err(|e| Error::ReleaseTokenInvalid(format!("beacon unreachable: {}", e)))?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            tracing::warn!("beacon token request failed: status={} body={}", status, body);
            return Err(Error::ReleaseTokenInvalid(format!(
                "beacon rejected request: status={} body={}",
                status, body
            )));
        }

        let token: ReleaseToken = resp
            .json()
            .await
            .map_err(|e| Error::ReleaseTokenInvalid(format!("invalid token response: {}", e)))?;

        token.verify(&self.center_verifying_key, oetp_core::release::current_timestamp_secs())?;

        Ok(token)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use oetp_core::signing;

    #[test]
    fn test_beacon_client_new() {
        let key = signing::generate_keypair();
        let vk_bytes = key.verifying_key().to_bytes();
        let client = BeaconClient::new("http://localhost:9090", &vk_bytes, "test-api-key").unwrap();
        assert_eq!(client.beacon_url, "http://localhost:9090");
    }
}
