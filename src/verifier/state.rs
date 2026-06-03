use std::collections::HashMap;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use tokio::sync::RwLock;

use crate::Statement;
use crate::error::StateError;

const CHALLENGE_EXPIRY_SECONDS: u64 = 300;
const MAX_CHALLENGES_PER_USER: usize = 3;
const SESSION_EXPIRY_SECONDS: u64 = 3600; // 1 hour
const MAX_SESSIONS_PER_USER: usize = 5;

const MAX_TOTAL_USERS: usize = 10_000;
const MAX_TOTAL_CHALLENGES: usize = 50_000;
const MAX_TOTAL_SESSIONS: usize = 100_000;

/// Registered user data.
#[derive(Clone, Debug)]
pub struct UserData {
    /// Unique identifier for the user.
    pub user_id: String,
    /// User's public statement (y1, y2).
    pub statement: Statement,
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

/// Active session data.
#[derive(Clone, Debug)]
pub struct SessionData {
    /// Session token (hex-encoded).
    pub token: String,
    /// User ID associated with this session.
    pub user_id: String,
    /// Unix timestamp when session was created.
    pub created_at: u64,
    /// Unix timestamp when session expires.
    pub expires_at: u64,
}

impl SessionData {
    /// Creates new session data with automatic expiry calculation.
    pub fn new(token: String, user_id: String) -> Self {
        let created_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_else(|_| unreachable!("System time is after UNIX_EPOCH"))
            .as_secs();
        let expires_at = created_at.saturating_add(SESSION_EXPIRY_SECONDS);

        Self {
            token,
            user_id,
            created_at,
            expires_at,
        }
    }

    /// Checks if the session has expired.
    pub fn is_expired(&self) -> bool {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_else(|_| unreachable!("System time is after UNIX_EPOCH"))
            .as_secs();

        now >= self.expires_at
    }
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

/// Server state managing users, active challenges, and sessions.
pub struct ServerState {
    users: Arc<RwLock<HashMap<String, UserData>>>,
    challenges: Arc<RwLock<HashMap<Vec<u8>, ChallengeData>>>,
    user_challenges: Arc<RwLock<HashMap<String, Vec<Vec<u8>>>>>,
    sessions: Arc<RwLock<HashMap<String, SessionData>>>,
    user_sessions: Arc<RwLock<HashMap<String, Vec<String>>>>,
}

impl ServerState {
    /// Creates new server state with empty registries.
    pub fn new() -> Self {
        Self {
            users: Arc::new(RwLock::new(HashMap::new())),
            challenges: Arc::new(RwLock::new(HashMap::new())),
            user_challenges: Arc::new(RwLock::new(HashMap::new())),
            sessions: Arc::new(RwLock::new(HashMap::new())),
            user_sessions: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Registers a new user with the provided data.
    pub async fn register_user(&self, user_data: UserData) -> Result<(), StateError> {
        let mut users = self.users.write().await;

        if users.len() >= MAX_TOTAL_USERS {
            return Err(StateError::CapacityExceeded { resource: "users" });
        }

        if users.contains_key(&user_data.user_id) {
            return Err(StateError::UserAlreadyExists);
        }

        users.insert(user_data.user_id.clone(), user_data);
        Ok(())
    }

    /// Retrieves user data by user ID.
    pub async fn get_user(&self, user_id: &str) -> Option<UserData> {
        let users = self.users.read().await;
        users.get(user_id).cloned()
    }

    /// Creates a new challenge for the specified user.
    pub async fn create_challenge(
        &self,
        user_id: &str,
        challenge_id: Vec<u8>,
    ) -> Result<u64, StateError> {
        let users = self.users.read().await;
        let mut user_challenges = self.user_challenges.write().await;
        let mut all_challenges = self.challenges.write().await;

        if all_challenges.len() >= MAX_TOTAL_CHALLENGES {
            return Err(StateError::CapacityExceeded {
                resource: "challenges",
            });
        }

        if !users.contains_key(user_id) {
            return Err(StateError::UserNotFound);
        }

        let challenges = user_challenges.entry(user_id.to_string()).or_default();

        if challenges.len() >= MAX_CHALLENGES_PER_USER {
            return Err(StateError::TooManyChallenges);
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
    pub async fn consume_challenge(
        &self,
        challenge_id: &[u8],
    ) -> Result<ChallengeData, StateError> {
        let mut challenges = self.challenges.write().await;
        let mut user_challenges = self.user_challenges.write().await;

        let challenge_data = challenges
            .get(challenge_id)
            .ok_or(StateError::ChallengeNotFound)?
            .clone();

        if challenge_data.is_expired() {
            challenges.remove(challenge_id);
            if let Some(user_challs) = user_challenges.get_mut(&challenge_data.user_id) {
                user_challs.retain(|id| id != challenge_id);
            }
            return Err(StateError::ChallengeNotFound);
        }

        challenges.remove(challenge_id);
        if let Some(user_challs) = user_challenges.get_mut(&challenge_data.user_id) {
            user_challs.retain(|id| id != challenge_id);
        }

        Ok(challenge_data)
    }

    /// Removes all expired challenges from the state.
    pub async fn cleanup_expired_challenges(&self) {
        let mut challenges = self.challenges.write().await;
        let mut user_challenges = self.user_challenges.write().await;

        let expired = challenges
            .iter()
            .filter(|(_, data)| data.is_expired())
            .map(|(id, _)| id.clone())
            .collect::<Vec<Vec<u8>>>();

        for challenge_id in expired {
            if let Some(data) = challenges.remove(&challenge_id) {
                if let Some(user_challs) = user_challenges.get_mut(&data.user_id) {
                    user_challs.retain(|id| id != &challenge_id);
                }
            }
        }
    }

    /// Creates a new session for the specified user.
    pub async fn create_session(&self, token: String, user_id: String) -> Result<(), StateError> {
        let mut sessions = self.sessions.write().await;
        let mut user_sessions = self.user_sessions.write().await;

        if sessions.len() >= MAX_TOTAL_SESSIONS {
            return Err(StateError::CapacityExceeded {
                resource: "sessions",
            });
        }

        let user_session_tokens = user_sessions.entry(user_id.clone()).or_default();
        if user_session_tokens.len() >= MAX_SESSIONS_PER_USER {
            return Err(StateError::TooManySessions);
        }

        let session_data = SessionData::new(token.clone(), user_id.clone());
        sessions.insert(token.clone(), session_data);
        user_session_tokens.push(token);

        Ok(())
    }

    /// Validates a session token.
    pub async fn validate_session(&self, token: &str) -> Result<String, StateError> {
        let sessions = self.sessions.read().await;

        let session_data = sessions.get(token).ok_or(StateError::SessionNotFound)?;

        if session_data.is_expired() {
            return Err(StateError::SessionExpired);
        }

        Ok(session_data.user_id.clone())
    }

    /// Revokes a session token.
    pub async fn revoke_session(&self, token: &str) -> Result<(), StateError> {
        let mut sessions = self.sessions.write().await;
        let mut user_sessions = self.user_sessions.write().await;

        let session_data = sessions.remove(token).ok_or(StateError::SessionNotFound)?;

        if let Some(user_session_tokens) = user_sessions.get_mut(&session_data.user_id) {
            user_session_tokens.retain(|t| t != token);
        }

        Ok(())
    }

    /// Removes all expired sessions from the state.
    pub async fn cleanup_expired_sessions(&self) {
        let mut sessions = self.sessions.write().await;
        let mut user_sessions = self.user_sessions.write().await;

        let expired = sessions
            .iter()
            .filter(|(_, data)| data.is_expired())
            .map(|(token, _)| token.clone())
            .collect::<Vec<String>>();

        for token in expired {
            if let Some(data) = sessions.remove(&token) {
                if let Some(user_session_tokens) = user_sessions.get_mut(&data.user_id) {
                    user_session_tokens.retain(|t| t != &token);
                }
            }
        }
    }

    /// Returns the number of registered users.
    pub async fn user_count(&self) -> usize {
        self.users.read().await.len()
    }

    /// Returns the number of active sessions.
    pub async fn session_count(&self) -> usize {
        self.sessions.read().await.len()
    }

    /// Returns the number of pending challenges.
    pub async fn challenge_count(&self) -> usize {
        self.challenges.read().await.len()
    }
}

impl Default for ServerState {
    fn default() -> Self {
        Self::new()
    }
}

impl Clone for ServerState {
    fn clone(&self) -> Self {
        Self {
            users: Arc::clone(&self.users),
            challenges: Arc::clone(&self.challenges),
            user_challenges: Arc::clone(&self.user_challenges),
            sessions: Arc::clone(&self.sessions),
            user_sessions: Arc::clone(&self.user_sessions),
        }
    }
}
