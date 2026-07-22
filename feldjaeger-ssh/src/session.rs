//! SSH session data models.

use crate::connection::ConnectionProfile;

/// Lifecycle state of an SSH session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionState {
    /// Connection is being established.
    Connecting,
    /// Session is active and ready for operations.
    Connected,
    /// Session has been closed.
    Disconnected,
}

/// Descriptive metadata for an established SSH session.
///
/// This is a data model only. Operational methods live on [`super::SshSession`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionInfo {
    /// Connection profile used to open the session.
    pub profile: ConnectionProfile,
    /// Current session lifecycle state.
    pub state: SessionState,
}

impl SessionInfo {
    /// Creates session metadata for a newly connected session.
    pub fn connected(profile: ConnectionProfile) -> Self {
        Self {
            profile,
            state: SessionState::Connected,
        }
    }
}
