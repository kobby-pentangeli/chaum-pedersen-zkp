use std::collections::HashMap;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use tokio::sync::RwLock;

use crate::{Error, Group, Result, Ristretto255, Statement};

const CHALLENGE_EXPIRY_SECONDS: u64 = 300;
const MAX_CHALLENGES_PER_USER: usize = 3;

/// Registered user data.
#[derive(Clone, Debug)]
pub struct UserData<G: Group> {
    /// Unique identifier for the user.
    pub user_id: String,
    /// User's public statement (y1, y2).
    pub statement: Statement<G>,
    /// Cryptographic group name.
    pub group_name: String,
    /// Unix timestamp of registration.
    pub registered_at: u64,
}

/// Active challenge data.
#[derive(Clone, Debug)]
pub struct ChallengeData {
    /// Unique challenge identifier.
    pub challenge_id: Vec<u8>,
    /// User ID associated with this challenge.
    pub user_id: String,
    /// Unix timestamp when challenge was created.
    pub created_at: u64,
    /// Unix timestamp when challenge expires.
    pub expires_at: u64,
}

impl ChallengeData {
    /// Creates new challenge data with automatic expiry calculation.
    pub fn new(challenge_id: Vec<u8>, user_id: String) -> Self {
        let created_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_else(|_| unreachable!("System time is after UNIX_EPOCH"))
            .as_secs();
        let expires_at = created_at.saturating_add(CHALLENGE_EXPIRY_SECONDS);

        Self {
            challenge_id,
            user_id,
            created_at,
            expires_at,
        }
    }

    /// Checks if the challenge has expired.
    ///
    /// Returns true if either the expiry timestamp has been reached OR
    /// if the challenge age exceeds twice the expiry duration (to handle clock skew).
    pub fn is_expired(&self) -> bool {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_else(|_| unreachable!("System time is after UNIX_EPOCH"))
            .as_secs();

        let max_duration = 2 * CHALLENGE_EXPIRY_SECONDS;
        let age = now.saturating_sub(self.created_at);

        now >= self.expires_at || age >= max_duration
    }
}

/// Server state managing users and active challenges.
///
/// Provides thread-safe access to user registry and challenge tracking
/// with automatic expiry and rate limiting.
pub struct ServerState<G: Group> {
    users: Arc<RwLock<HashMap<String, UserData<G>>>>,
    challenges: Arc<RwLock<HashMap<Vec<u8>, ChallengeData>>>,
    user_challenges: Arc<RwLock<HashMap<String, Vec<Vec<u8>>>>>,
}

impl<G: Group> ServerState<G> {
    /// Creates new server state with empty registries.
    pub fn new() -> Self {
        Self {
            users: Arc::new(RwLock::new(HashMap::new())),
            challenges: Arc::new(RwLock::new(HashMap::new())),
            user_challenges: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Registers a new user with the provided data.
    ///
    /// Returns an error if the user ID is already registered.
    pub async fn register_user(&self, user_data: UserData<G>) -> Result<()> {
        let mut users = self.users.write().await;

        if users.contains_key(&user_data.user_id) {
            return Err(Error::InvalidParams(format!(
                "User '{}' already registered",
                user_data.user_id
            )));
        }

        users.insert(user_data.user_id.clone(), user_data);
        Ok(())
    }

    /// Retrieves user data by user ID.
    pub async fn get_user(&self, user_id: &str) -> Option<UserData<G>> {
        let users = self.users.read().await;
        users.get(user_id).cloned()
    }

    /// Creates a new challenge for the specified user.
    ///
    /// Returns the challenge expiry timestamp in seconds since UNIX epoch.
    /// Returns an error if the user is not found or has too many active challenges.
    pub async fn create_challenge(&self, user_id: &str, challenge_id: Vec<u8>) -> Result<u64> {
        let users = self.users.read().await;
        let mut user_challenges = self.user_challenges.write().await;
        let mut all_challenges = self.challenges.write().await;

        if !users.contains_key(user_id) {
            return Err(Error::InvalidParams(format!("User '{user_id}' not found")));
        }

        let challenges = user_challenges.entry(user_id.to_string()).or_default();

        if challenges.len() >= MAX_CHALLENGES_PER_USER {
            return Err(Error::InvalidParams(format!(
                "Too many active challenges for user '{user_id}'"
            )));
        }

        let challenge_data = ChallengeData::new(challenge_id.clone(), user_id.to_string());
        let expires_at = challenge_data.expires_at;

        challenges.push(challenge_id.clone());
        all_challenges.insert(challenge_id, challenge_data);

        Ok(expires_at)
    }

    /// Retrieves challenge data by challenge ID.
    pub async fn get_challenge(&self, challenge_id: &[u8]) -> Option<ChallengeData> {
        let challenges = self.challenges.read().await;
        challenges.get(challenge_id).cloned()
    }

    /// Consumes a challenge, removing it from active challenges.
    ///
    /// Returns an error if the challenge is not found or has expired.
    pub async fn consume_challenge(&self, challenge_id: &[u8]) -> Result<ChallengeData> {
        let mut challenges = self.challenges.write().await;
        let challenge_data = challenges
            .remove(challenge_id)
            .ok_or_else(|| Error::InvalidParams("Challenge not found".to_string()))?;

        if challenge_data.is_expired() {
            return Err(Error::InvalidParams("Challenge expired".to_string()));
        }

        let mut user_challenges = self.user_challenges.write().await;
        if let Some(user_challs) = user_challenges.get_mut(&challenge_data.user_id) {
            user_challs.retain(|id| id != challenge_id);
        }

        Ok(challenge_data)
    }

    /// Removes all expired challenges from the state.
    pub async fn cleanup_expired_challenges(&self) {
        let mut challenges = self.challenges.write().await;
        let mut user_challenges = self.user_challenges.write().await;

        let expired: Vec<Vec<u8>> = challenges
            .iter()
            .filter(|(_, data)| data.is_expired())
            .map(|(id, _)| id.clone())
            .collect();

        for challenge_id in expired {
            if let Some(data) = challenges.remove(&challenge_id) {
                if let Some(user_challs) = user_challenges.get_mut(&data.user_id) {
                    user_challs.retain(|id| id != &challenge_id);
                }
            }
        }
    }
}

impl<G: Group> Default for ServerState<G> {
    fn default() -> Self {
        Self::new()
    }
}

impl<G: Group> Clone for ServerState<G> {
    fn clone(&self) -> Self {
        Self {
            users: Arc::clone(&self.users),
            challenges: Arc::clone(&self.challenges),
            user_challenges: Arc::clone(&self.user_challenges),
        }
    }
}

/// Type alias for server state using Ristretto255 group.
pub type DefaultServerState = ServerState<Ristretto255>;
