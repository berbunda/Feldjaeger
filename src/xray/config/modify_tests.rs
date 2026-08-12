//! Tests for VLESS client add / update / delete and write-back safety.

use std::collections::BTreeMap;
use std::future;
use std::sync::{Arc, Mutex};

use feldjaeger_ssh::{ConnectionProfile, RemotePath, SshSession};
use serde_json::Value;

use super::XrayConfigParser;
use super::editable::EditableXrayConfig;
use super::inbound_clients::InboundClientProtocol;
use super::inbound_edit::{
    InboundGeneral, InboundRef, SniffingSettings, SniffingWriteOutcome, KNOWN_DEST_OVERRIDE,
};
use super::modify::{
    AddOutboundRequest, AddOutboundShellRequest, AddUserRequest, DeleteUserRequest,
    RemoveOutboundRequest, ReplaceOutboundRequest, UpdateInboundGeneralRequest,
    UpdateInboundSniffingRequest, UpdateLogSettingsRequest, UpdateOutboundShellRequest,
    UpdateUserRequest, add_outbound, add_outbound_shell, add_user, delete_user,
    generate_client_uuid, remove_outbound, replace_outbound, update_inbound_general,
    update_inbound_sniffing, update_log_settings, update_outbound_shell, update_user,
};
use super::modify_error::ConfigModifyErrorKind;
use super::serialize::validate_serialized_json;
use super::users::extract_vless_clients;
use crate::remote::RemoteAdmin;

fn single_file_editable(json: &str) -> EditableXrayConfig {
    let parser = XrayConfigParser::new();
    let outcome = parser.parse_single_file("/etc/xray/config.json", json);
    assert!(outcome.is_success(), "{:?}", outcome.errors());
    let root: Value = serde_json::from_str(json).expect("json");
    EditableXrayConfig::from_single_file("/etc/xray/config.json", root, outcome.into_sections())
}

fn directory_editable(files: &[(&str, &str)]) -> EditableXrayConfig {
    let parser = XrayConfigParser::new();
    let owned: Vec<(String, String)> = files
        .iter()
        .map(|(path, text)| ((*path).to_owned(), (*text).to_owned()))
        .collect();
    let outcome = parser.parse_directory(owned.iter().map(|(p, t)| (p.as_str(), t.as_str())));
    assert!(outcome.is_success(), "{:?}", outcome.errors());
    let mut roots = BTreeMap::new();
    for (path, text) in &owned {
        roots.insert(path.clone(), serde_json::from_str(text).expect("json"));
    }
    EditableXrayConfig::new(outcome.into_sections(), roots)
}

#[test]
fn add_user_appends_client_and_generates_uuid() {
    let mut config = single_file_editable(
        r#"{
            "inbounds":[{
                "tag":"vless-in",
                "protocol":"vless",
                "settings":{"clients":[{"id":"existing","email":"a@example.com"}],"decryption":"none"}
            }]
        }"#,
    );

    let outcome = add_user(
        &mut config,
        AddUserRequest {
            inbound_index: 0,
            email: "new@example.com".to_owned(),
            id: None,
            flow: None,
            level: 0,
        },
    )
    .expect("add should succeed");

    assert_eq!(outcome.source_file, "/etc/xray/config.json");
    let clients = extract_vless_clients(config.sections());
    assert_eq!(clients.len(), 2);
    assert_eq!(clients[1].email.as_deref(), Some("new@example.com"));
    let id = clients[1].id.as_deref().expect("uuid");
    assert!(uuid::Uuid::parse_str(id).is_ok());
    assert!(clients[1].flow.is_none());

    let root = config.file_roots().get("/etc/xray/config.json").unwrap();
    let added = &root["inbounds"][0]["settings"]["clients"][1];
    assert!(added.get("flow").is_none());
    assert_eq!(added["email"], "new@example.com");
}

#[test]
fn add_user_preserves_optional_flow_when_set() {
    let mut config = single_file_editable(
        r#"{
            "inbounds":[{
                "protocol":"vless",
                "settings":{"clients":[],"decryption":"none"}
            }]
        }"#,
    );

    add_user(
        &mut config,
        AddUserRequest {
            inbound_index: 0,
            email: "vision@example.com".to_owned(),
            id: Some("11111111-1111-4111-8111-111111111111".to_owned()),
            flow: Some("xtls-rprx-vision".to_owned()),
            level: 0,
        },
    )
    .expect("add");

    let client =
        &config.file_roots()["/etc/xray/config.json"]["inbounds"][0]["settings"]["clients"][0];
    assert_eq!(client["flow"], "xtls-rprx-vision");
}

#[test]
fn add_user_vision_on_xhttp_rejected_by_g3() {
    let mut config = single_file_editable(
        r#"{
            "inbounds":[{
                "protocol":"vless",
                "settings":{"clients":[],"decryption":"none"},
                "streamSettings":{"network":"xhttp","security":"none"}
            }]
        }"#,
    );

    let err = add_user(
        &mut config,
        AddUserRequest {
            inbound_index: 0,
            email: "vision@example.com".to_owned(),
            id: Some("11111111-1111-4111-8111-111111111111".to_owned()),
            flow: Some("xtls-rprx-vision".to_owned()),
            level: 0,
        },
    )
    .expect_err("Vision + xhttp must fail G3");

    assert_eq!(err.kind(), ConfigModifyErrorKind::ValidationFailed);
    assert!(
        err.detail().contains("vision") || err.detail().contains("raw/tcp"),
        "{}",
        err.detail()
    );

    let clients = &config.file_roots()["/etc/xray/config.json"]["inbounds"][0]["settings"]["clients"];
    assert!(clients.as_array().is_some_and(|a| a.is_empty()));
}

#[test]
fn update_user_vision_on_xhttp_rejected_by_g3() {
    let mut config = single_file_editable(
        r#"{
            "inbounds":[{
                "protocol":"vless",
                "settings":{
                    "clients":[{"id":"keep-me","email":"old@example.com"}],
                    "decryption":"none"
                },
                "streamSettings":{"network":"xhttp","security":"none"}
            }]
        }"#,
    );

    let err = update_user(
        &mut config,
        UpdateUserRequest {
            inbound_index: 0,
            client_index: 0,
            email: "old@example.com".to_owned(),
            flow: Some("xtls-rprx-vision".to_owned()),
            level: 0,
            expected_fingerprint: None,
        },
    )
    .expect_err("Vision + xhttp must fail G3");

    assert_eq!(err.kind(), ConfigModifyErrorKind::ValidationFailed);
    let client =
        &config.file_roots()["/etc/xray/config.json"]["inbounds"][0]["settings"]["clients"][0];
    assert!(client.get("flow").is_none());
}

#[test]
fn update_user_changes_email_and_flow_keeps_uuid_and_unknown_fields() {
    let mut config = single_file_editable(
        r#"{
            "inbounds":[{
                "protocol":"vless",
                "settings":{
                    "clients":[{
                        "id":"keep-me",
                        "email":"old@example.com",
                        "flow":"xtls-rprx-vision",
                        "futureField":"keep"
                    }],
                    "decryption":"none"
                }
            }]
        }"#,
    );

    update_user(
        &mut config,
        UpdateUserRequest {
            inbound_index: 0,
            client_index: 0,
            email: "new@example.com".to_owned(),
            flow: Some("xtls-rprx-vision".to_owned()),
            level: 0,
            expected_fingerprint: None,
        },
    )
    .expect("update");

    let client =
        &config.file_roots()["/etc/xray/config.json"]["inbounds"][0]["settings"]["clients"][0];
    assert_eq!(client["id"], "keep-me");
    assert_eq!(client["email"], "new@example.com");
    assert_eq!(client["flow"], "xtls-rprx-vision");
    assert_eq!(client["futureField"], "keep");
}

#[test]
fn update_user_clears_flow_when_empty() {
    let mut config = single_file_editable(
        r#"{
            "inbounds":[{
                "protocol":"vless",
                "settings":{
                    "clients":[{"id":"u","email":"a@example.com","flow":"xtls-rprx-vision"}],
                    "decryption":"none"
                }
            }]
        }"#,
    );

    update_user(
        &mut config,
        UpdateUserRequest {
            inbound_index: 0,
            client_index: 0,
            email: "a@example.com".to_owned(),
            flow: None,
            level: 0,
            expected_fingerprint: None,
        },
    )
    .expect("update");

    let client =
        &config.file_roots()["/etc/xray/config.json"]["inbounds"][0]["settings"]["clients"][0];
    assert!(client.get("flow").is_none());
}

#[test]
fn delete_user_removes_only_selected_client() {
    let mut config = single_file_editable(
        r#"{
            "inbounds":[{
                "protocol":"vless",
                "settings":{
                    "clients":[
                        {"id":"u1","email":"a@example.com"},
                        {"id":"u2","email":"b@example.com"},
                        {"id":"u3","email":"c@example.com"}
                    ],
                    "decryption":"none"
                }
            }]
        }"#,
    );

    delete_user(
        &mut config,
        DeleteUserRequest {
            inbound_index: 0,
            client_index: 1,
            expected_fingerprint: None,
        },
    )
    .expect("delete");

    let clients = extract_vless_clients(config.sections());
    assert_eq!(clients.len(), 2);
    assert_eq!(clients[0].email.as_deref(), Some("a@example.com"));
    assert_eq!(clients[1].email.as_deref(), Some("c@example.com"));
}

#[test]
fn delete_missing_user_fails() {
    let mut config = single_file_editable(
        r#"{
            "inbounds":[{
                "protocol":"vless",
                "settings":{"clients":[{"id":"u1","email":"a@example.com"}],"decryption":"none"}
            }]
        }"#,
    );

    let error = delete_user(
        &mut config,
        DeleteUserRequest {
            inbound_index: 0,
            client_index: 5,
            expected_fingerprint: None,
        },
    )
    .expect_err("missing user");
    assert_eq!(error.kind(), ConfigModifyErrorKind::UserNotFound);
}

#[test]
fn unsupported_inbound_rejected() {
    let mut config = single_file_editable(
        r#"{
            "inbounds":[{
                "protocol":"vmess",
                "settings":{"clients":[{"id":"u1","email":"a@example.com"}]}
            }]
        }"#,
    );

    let error = add_user(
        &mut config,
        AddUserRequest {
            inbound_index: 0,
            email: "x@example.com".to_owned(),
            id: None,
            flow: None,
            level: 0,
        },
    )
    .expect_err("vmess unsupported");
    assert_eq!(error.kind(), ConfigModifyErrorKind::UnsupportedInbound);
    assert_eq!(error.message(), "Unsupported inbound type");
}

#[test]
fn config_directory_modifies_only_affected_file() {
    let mut config = directory_editable(&[
        (
            "/etc/xray/01-inbounds.json",
            r#"{
                "inbounds":[{
                    "tag":"vless-in",
                    "protocol":"vless",
                    "settings":{"clients":[{"id":"u1","email":"a@example.com"}],"decryption":"none"}
                }]
            }"#,
        ),
        (
            "/etc/xray/02-routing.json",
            r#"{"routing":{"domainStrategy":"AsIs","rules":[]}}"#,
        ),
    ]);

    let routing_before = config.file_roots()["/etc/xray/02-routing.json"].clone();

    let outcome = add_user(
        &mut config,
        AddUserRequest {
            inbound_index: 0,
            email: "b@example.com".to_owned(),
            id: Some("u2".to_owned()),
            flow: None,
            level: 0,
        },
    )
    .expect("add");

    assert_eq!(outcome.source_file, "/etc/xray/01-inbounds.json");
    assert_eq!(
        config.file_roots()["/etc/xray/02-routing.json"],
        routing_before
    );
    assert!(
        config
            .serialize_source_file("/etc/xray/02-routing.json")
            .is_ok()
    );
}

#[tokio::test]
async fn backup_created_before_write_and_backup_failure_aborts() {
    let original = RemotePath::new("/etc/xray/config.json").unwrap();
    let files = Arc::new(Mutex::new(BTreeMap::from([(
        original.as_str().to_owned(),
        br#"{"inbounds":[]}"#.to_vec(),
    )])));

    #[derive(Clone)]
    struct Session {
        profile: ConnectionProfile,
        files: Arc<Mutex<BTreeMap<String, Vec<u8>>>>,
        fail_backup_write: bool,
    }

    impl SshSession for Session {
        fn profile(&self) -> &ConnectionProfile {
            &self.profile
        }

        fn read_file(
            &self,
            path: &RemotePath,
        ) -> impl Future<Output = feldjaeger_ssh::SshResult<Vec<u8>>> + Send {
            let result = self
                .files
                .lock()
                .unwrap()
                .get(path.as_str())
                .cloned()
                .ok_or_else(|| {
                    feldjaeger_ssh::SshError::new(format!("file not found: {}", path.as_str()))
                });
            future::ready(result)
        }

        fn write_file(
            &self,
            path: &RemotePath,
            contents: &[u8],
        ) -> impl Future<Output = feldjaeger_ssh::SshResult<()>> + Send {
            if self.fail_backup_write && path.as_str().contains(".feldjaeger.bak.") {
                return future::ready(Err(feldjaeger_ssh::SshError::new(
                    "permission denied writing backup",
                )));
            }
            self.files
                .lock()
                .unwrap()
                .insert(path.as_str().to_owned(), contents.to_vec());
            future::ready(Ok(()))
        }

        fn write_file_atomic(
            &self,
            path: &RemotePath,
            contents: &[u8],
        ) -> impl Future<Output = feldjaeger_ssh::SshResult<()>> + Send {
            self.write_file(path, contents)
        }

        fn rename_file(
            &self,
            from: &RemotePath,
            to: &RemotePath,
        ) -> impl Future<Output = feldjaeger_ssh::SshResult<()>> + Send {
            let mut files = self.files.lock().unwrap();
            let value = files.remove(from.as_str()).unwrap();
            files.insert(to.as_str().to_owned(), value);
            future::ready(Ok(()))
        }

        fn remove_file(
            &self,
            path: &RemotePath,
        ) -> impl Future<Output = feldjaeger_ssh::SshResult<()>> + Send {
            self.files.lock().unwrap().remove(path.as_str());
            future::ready(Ok(()))
        }

        fn path_is_file(
            &self,
            path: &RemotePath,
        ) -> impl Future<Output = feldjaeger_ssh::SshResult<bool>> + Send {
            let is_file = self.files.lock().unwrap().contains_key(path.as_str());
            future::ready(Ok(is_file))
        }

        fn exec(
            &self,
            _command: &feldjaeger_ssh::RemoteCommand,
        ) -> impl Future<Output = feldjaeger_ssh::SshResult<feldjaeger_ssh::ExecResult>> + Send
        {
            future::ready(Err(feldjaeger_ssh::SshError::new("unused")))
        }

    fn exec_with_stdin(
        &self,
        command: &feldjaeger_ssh::RemoteCommand,
        stdin: &[u8],
    ) -> impl Future<Output = feldjaeger_ssh::SshResult<feldjaeger_ssh::ExecResult>> + Send {
        let _ = stdin;
        self.exec(command)
    }

        fn disconnect(self) -> impl Future<Output = feldjaeger_ssh::SshResult<()>> + Send {
            future::ready(Ok(()))
        }
    }

    let session = Session {
        profile: ConnectionProfile::new("127.0.0.1", 22, "admin"),
        files: Arc::clone(&files),
        fail_backup_write: false,
    };
    let admin = RemoteAdmin::new();
    admin
        .write_config_safe(&session, &original, br#"{"inbounds":[{"tag":"x"}]}"#)
        .await
        .expect("write");

    {
        let stored = files.lock().unwrap();
        assert!(stored.keys().any(|key| key.contains(".feldjaeger.bak.")));
        assert_eq!(
            stored.get(original.as_str()).map(Vec::as_slice),
            Some(br#"{"inbounds":[{"tag":"x"}]}"#.as_slice())
        );
    }

    let failing = Session {
        profile: ConnectionProfile::new("127.0.0.1", 22, "admin"),
        files: Arc::new(Mutex::new(BTreeMap::from([(
            original.as_str().to_owned(),
            br#"{"inbounds":[]}"#.to_vec(),
        )]))),
        fail_backup_write: true,
    };
    let error = admin
        .write_config_safe(&failing, &original, br#"{"broken":true}"#)
        .await
        .expect_err("backup failure aborts");
    assert!(error.message().starts_with("Backup failed"));
    assert_eq!(
        failing
            .files
            .lock()
            .unwrap()
            .get(original.as_str())
            .map(Vec::as_slice),
        Some(br#"{"inbounds":[]}"#.as_slice())
    );
}

#[test]
fn invalid_serialized_config_rejected_before_upload() {
    let error = validate_serialized_json(b"not-json").expect_err("invalid");
    assert_eq!(error.kind(), ConfigModifyErrorKind::ValidationFailed);
}

#[test]
fn generate_client_uuid_is_valid_v4() {
    let value = generate_client_uuid();
    let parsed = uuid::Uuid::parse_str(&value).expect("uuid");
    assert_eq!(parsed.get_version(), Some(uuid::Version::Random));
}

#[test]
fn email_conflict_rejected() {
    let mut config = single_file_editable(
        r#"{
            "inbounds":[{
                "protocol":"vless",
                "settings":{"clients":[{"id":"u1","email":"a@example.com"}],"decryption":"none"}
            }]
        }"#,
    );
    let error = add_user(
        &mut config,
        AddUserRequest {
            inbound_index: 0,
            email: "a@example.com".to_owned(),
            id: None,
            flow: None,
            level: 0,
        },
    )
    .expect_err("conflict");
    assert_eq!(error.kind(), ConfigModifyErrorKind::EmailConflict);
}

#[test]
fn update_log_settings_creates_missing_log_object_on_save() {
    let mut config = single_file_editable(r#"{"inbounds":[]}"#);
    assert!(config.sections().log().is_none());

    let mut settings = config.log_settings();
    assert!(!settings.section_present);
    settings.access = super::log_settings::LogOutput::File("/var/log/xray/access.log".to_owned());
    settings.log_level = super::log_settings::LogLevel::Info;
    settings.dns_log = true;

    let outcome = update_log_settings(
        &mut config,
        UpdateLogSettingsRequest {
            settings: settings.clone(),
        },
    )
    .expect("save should create log object");

    assert_eq!(outcome.source_file, "/etc/xray/config.json");
    let root = config.file_roots().get("/etc/xray/config.json").unwrap();
    assert_eq!(root["log"]["access"], "/var/log/xray/access.log");
    assert_eq!(root["log"]["loglevel"], "info");
    assert_eq!(root["log"]["dnsLog"], true);
    assert!(config.sections().log().is_some());
}

#[test]
fn update_log_settings_preserves_unknown_fields() {
    let mut config = single_file_editable(
        r#"{
            "log": {
                "loglevel": "warning",
                "futureField": true,
                "extra": {"nested": 1}
            }
        }"#,
    );
    let mut settings = config.log_settings();
    settings.log_level = super::log_settings::LogLevel::Debug;
    update_log_settings(
        &mut config,
        UpdateLogSettingsRequest { settings },
    )
    .expect("update");

    let root = config.file_roots().get("/etc/xray/config.json").unwrap();
    assert_eq!(root["log"]["futureField"], true);
    assert_eq!(root["log"]["extra"]["nested"], 1);
    assert_eq!(root["log"]["loglevel"], "debug");
}

#[test]
fn update_log_settings_rejects_invalid_path() {
    let mut config = single_file_editable(r#"{"log":{"loglevel":"warning"}}"#);
    let mut settings = config.log_settings();
    settings.access = super::log_settings::LogOutput::File("relative.log".to_owned());
    let error = update_log_settings(
        &mut config,
        UpdateLogSettingsRequest { settings },
    )
    .expect_err("invalid path");
    assert_eq!(error.kind(), ConfigModifyErrorKind::InvalidFilePath);
}

#[test]
fn update_log_settings_rejects_invalid_custom_mask() {
    let mut config = single_file_editable(r#"{"log":{"loglevel":"warning"}}"#);
    let mut settings = config.log_settings();
    settings.mask_address = super::log_settings::MaskAddress::Custom("/12+/32".to_owned());
    let error = update_log_settings(
        &mut config,
        UpdateLogSettingsRequest { settings },
    )
    .expect_err("invalid mask");
    assert_eq!(error.kind(), ConfigModifyErrorKind::InvalidMaskFormat);
}

#[test]
fn update_log_settings_keeps_unknown_mask_until_changed() {
    let mut config = single_file_editable(r#"{"log":{"maskAddress":"weird"}}"#);
    let settings = config.log_settings();
    assert!(matches!(
        settings.mask_address,
        super::log_settings::MaskAddress::Unknown(_)
    ));
    update_log_settings(
        &mut config,
        UpdateLogSettingsRequest {
            settings: settings.clone(),
        },
    )
    .expect("preserve unknown");
    let root = config.file_roots().get("/etc/xray/config.json").unwrap();
    assert_eq!(root["log"]["maskAddress"], "weird");
}

#[test]
fn update_log_settings_confdir_writes_owning_file_only() {
    let mut config = directory_editable(&[
        ("/cfg/01-log.json", r#"{"log":{"loglevel":"warning"}}"#),
        (
            "/cfg/02-inbounds.json",
            r#"{"inbounds":[{"protocol":"vless","settings":{"clients":[],"decryption":"none"}}]}"#,
        ),
    ]);
    let mut settings = config.log_settings();
    settings.access = super::log_settings::LogOutput::Disabled;
    let outcome = update_log_settings(
        &mut config,
        UpdateLogSettingsRequest { settings },
    )
    .expect("update");
    assert_eq!(outcome.source_file, "/cfg/01-log.json");
    assert_eq!(
        config.file_roots().get("/cfg/01-log.json").unwrap()["log"]["access"],
        "none"
    );
    assert_eq!(
        config.file_roots().get("/cfg/02-inbounds.json").unwrap()["inbounds"][0]["protocol"],
        "vless"
    );
}

#[tokio::test]
async fn update_log_settings_backup_failure_aborts_write() {
    use crate::app::{ConnectionSecrets, run_update_log_settings};
    use crate::storage::StoredConnectionProfile;
    use feldjaeger_ssh::{AuthMethod, ConnectionProfile, SshBackend, SshSession};

    let config = single_file_editable(r#"{"log":{"loglevel":"warning","access":""}}"#);
    let original = config
        .serialize_source_file("/etc/xray/config.json")
        .expect("serialize");

    let mut settings = config.log_settings();
    settings.log_level = super::log_settings::LogLevel::Info;

    struct Backend {
        files: Arc<Mutex<BTreeMap<String, Vec<u8>>>>,
        fail_backup: bool,
    }

    impl SshBackend for Backend {
        type Session = Session;
        fn connect(
            &self,
            request: &feldjaeger_ssh::ConnectRequest,
        ) -> impl Future<Output = feldjaeger_ssh::SshResult<Self::Session>> + Send {
            let _ = request;
            future::ready(Ok(Session {
                profile: ConnectionProfile::new("127.0.0.1", 22, "admin"),
                files: Arc::clone(&self.files),
                fail_backup: self.fail_backup,
            }))
        }
    }

    struct Session {
        profile: ConnectionProfile,
        files: Arc<Mutex<BTreeMap<String, Vec<u8>>>>,
        fail_backup: bool,
    }

    impl SshSession for Session {
        fn profile(&self) -> &ConnectionProfile {
            &self.profile
        }
        fn read_file(
            &self,
            path: &RemotePath,
        ) -> impl Future<Output = feldjaeger_ssh::SshResult<Vec<u8>>> + Send {
            let value = self
                .files
                .lock()
                .unwrap()
                .get(path.as_str())
                .cloned()
                .unwrap_or_default();
            future::ready(Ok(value))
        }
        fn write_file(
            &self,
            path: &RemotePath,
            contents: &[u8],
        ) -> impl Future<Output = feldjaeger_ssh::SshResult<()>> + Send {
            if self.fail_backup && path.as_str().contains(".feldjaeger.bak.") {
                return future::ready(Err(feldjaeger_ssh::SshError::new("backup write denied")));
            }
            self.files
                .lock()
                .unwrap()
                .insert(path.as_str().to_owned(), contents.to_vec());
            future::ready(Ok(()))
        }
        fn write_file_atomic(
            &self,
            path: &RemotePath,
            contents: &[u8],
        ) -> impl Future<Output = feldjaeger_ssh::SshResult<()>> + Send {
            self.write_file(path, contents)
        }
        fn rename_file(
            &self,
            from: &RemotePath,
            to: &RemotePath,
        ) -> impl Future<Output = feldjaeger_ssh::SshResult<()>> + Send {
            let mut files = self.files.lock().unwrap();
            let value = files.remove(from.as_str()).unwrap();
            files.insert(to.as_str().to_owned(), value);
            future::ready(Ok(()))
        }
        fn remove_file(
            &self,
            path: &RemotePath,
        ) -> impl Future<Output = feldjaeger_ssh::SshResult<()>> + Send {
            self.files.lock().unwrap().remove(path.as_str());
            future::ready(Ok(()))
        }
        fn path_is_file(
            &self,
            path: &RemotePath,
        ) -> impl Future<Output = feldjaeger_ssh::SshResult<bool>> + Send {
            let is_file = self.files.lock().unwrap().contains_key(path.as_str());
            future::ready(Ok(is_file))
        }
        fn exec(
            &self,
            _command: &feldjaeger_ssh::RemoteCommand,
        ) -> impl Future<Output = feldjaeger_ssh::SshResult<feldjaeger_ssh::ExecResult>> + Send
        {
            future::ready(Err(feldjaeger_ssh::SshError::new("unused")))
        }

    fn exec_with_stdin(
        &self,
        command: &feldjaeger_ssh::RemoteCommand,
        stdin: &[u8],
    ) -> impl std::future::Future<Output = feldjaeger_ssh::SshResult<feldjaeger_ssh::ExecResult>> + Send {
        let _ = stdin;
        self.exec(command)
    }

        fn disconnect(self) -> impl Future<Output = feldjaeger_ssh::SshResult<()>> + Send {
            future::ready(Ok(()))
        }
    }

    let files = Arc::new(Mutex::new(BTreeMap::from([(
        "/etc/xray/config.json".to_owned(),
        original,
    )])));
    let backend = Backend {
        files: Arc::clone(&files),
        fail_backup: true,
    };
    let profile = StoredConnectionProfile {
        profile_name: "t".to_owned(),
        host: "127.0.0.1".to_owned(),
        port: 22,
        username: "admin".to_owned(),
        auth_method: AuthMethod::Password,
        private_key_path: String::new(),
    };
    let outcome = run_update_log_settings(
        &backend,
        &profile,
        &ConnectionSecrets::new(),
        &RemoteAdmin::new(),
        config,
        UpdateLogSettingsRequest { settings },
        crate::app::config_write::RemoteConfigValidateHint::skip(),
    )
    .await;

    let error = outcome.result.expect_err("backup failure");
    assert_eq!(error.kind(), ConfigModifyErrorKind::BackupFailed);
    let stored = files.lock().unwrap();
    let content = String::from_utf8_lossy(stored.get("/etc/xray/config.json").unwrap());
    assert!(content.contains("warning"));
}

#[tokio::test]
async fn update_log_settings_detects_remote_conflict() {
    use crate::app::{ConnectionSecrets, run_update_log_settings};
    use crate::storage::StoredConnectionProfile;
    use feldjaeger_ssh::{AuthMethod, ConnectionProfile, SshBackend, SshSession};

    let config = single_file_editable(r#"{"log":{"loglevel":"warning"}}"#);
    let mut settings = config.log_settings();
    settings.log_level = super::log_settings::LogLevel::Info;

    struct Backend {
        files: Arc<Mutex<BTreeMap<String, Vec<u8>>>>,
    }
    impl SshBackend for Backend {
        type Session = Session;
        fn connect(
            &self,
            request: &feldjaeger_ssh::ConnectRequest,
        ) -> impl Future<Output = feldjaeger_ssh::SshResult<Self::Session>> + Send {
            let _ = request;
            future::ready(Ok(Session {
                profile: ConnectionProfile::new("127.0.0.1", 22, "admin"),
                files: Arc::clone(&self.files),
            }))
        }
    }
    struct Session {
        profile: ConnectionProfile,
        files: Arc<Mutex<BTreeMap<String, Vec<u8>>>>,
    }
    impl SshSession for Session {
        fn profile(&self) -> &ConnectionProfile {
            &self.profile
        }
        fn read_file(
            &self,
            path: &RemotePath,
        ) -> impl Future<Output = feldjaeger_ssh::SshResult<Vec<u8>>> + Send {
            let value = self
                .files
                .lock()
                .unwrap()
                .get(path.as_str())
                .cloned()
                .unwrap_or_default();
            future::ready(Ok(value))
        }
        fn write_file(
            &self,
            path: &RemotePath,
            contents: &[u8],
        ) -> impl Future<Output = feldjaeger_ssh::SshResult<()>> + Send {
            self.files
                .lock()
                .unwrap()
                .insert(path.as_str().to_owned(), contents.to_vec());
            future::ready(Ok(()))
        }
        fn write_file_atomic(
            &self,
            path: &RemotePath,
            contents: &[u8],
        ) -> impl Future<Output = feldjaeger_ssh::SshResult<()>> + Send {
            self.write_file(path, contents)
        }
        fn rename_file(
            &self,
            from: &RemotePath,
            to: &RemotePath,
        ) -> impl Future<Output = feldjaeger_ssh::SshResult<()>> + Send {
            let mut files = self.files.lock().unwrap();
            let value = files.remove(from.as_str()).unwrap();
            files.insert(to.as_str().to_owned(), value);
            future::ready(Ok(()))
        }
        fn remove_file(
            &self,
            path: &RemotePath,
        ) -> impl Future<Output = feldjaeger_ssh::SshResult<()>> + Send {
            self.files.lock().unwrap().remove(path.as_str());
            future::ready(Ok(()))
        }
        fn path_is_file(
            &self,
            path: &RemotePath,
        ) -> impl Future<Output = feldjaeger_ssh::SshResult<bool>> + Send {
            let is_file = self.files.lock().unwrap().contains_key(path.as_str());
            future::ready(Ok(is_file))
        }
        fn exec(
            &self,
            _command: &feldjaeger_ssh::RemoteCommand,
        ) -> impl Future<Output = feldjaeger_ssh::SshResult<feldjaeger_ssh::ExecResult>> + Send
        {
            future::ready(Err(feldjaeger_ssh::SshError::new("unused")))
        }

    fn exec_with_stdin(
        &self,
        command: &feldjaeger_ssh::RemoteCommand,
        stdin: &[u8],
    ) -> impl std::future::Future<Output = feldjaeger_ssh::SshResult<feldjaeger_ssh::ExecResult>> + Send {
        let _ = stdin;
        self.exec(command)
    }

        fn disconnect(self) -> impl Future<Output = feldjaeger_ssh::SshResult<()>> + Send {
            future::ready(Ok(()))
        }
    }

    let backend = Backend {
        files: Arc::new(Mutex::new(BTreeMap::from([(
            "/etc/xray/config.json".to_owned(),
            br#"{"log":{"loglevel":"error","changed":true}}"#.to_vec(),
        )]))),
    };
    let profile = StoredConnectionProfile {
        profile_name: "t".to_owned(),
        host: "127.0.0.1".to_owned(),
        port: 22,
        username: "admin".to_owned(),
        auth_method: AuthMethod::Password,
        private_key_path: String::new(),
    };
    let outcome = run_update_log_settings(
        &backend,
        &profile,
        &ConnectionSecrets::new(),
        &RemoteAdmin::new(),
        config,
        UpdateLogSettingsRequest { settings },
        crate::app::config_write::RemoteConfigValidateHint::skip(),
    )
    .await;
    let error = outcome.result.expect_err("conflict");
    assert_eq!(
        error.kind(),
        ConfigModifyErrorKind::ConfigurationChangedRemotely
    );
}

#[test]
fn log_source_view_refreshes_after_log_settings_update() {
    use crate::xray::logs::{XrayLogDestination, log_config_view};

    let mut config = single_file_editable(
        r#"{"log":{"access":"/var/log/xray/access.log","error":"","loglevel":"warning"}}"#,
    );
    let before = log_config_view(config.sections().log());
    assert!(matches!(before.access, XrayLogDestination::File { .. }));

    let mut settings = config.log_settings();
    settings.access = super::log_settings::LogOutput::Disabled;
    settings.error = super::log_settings::LogOutput::File("/var/log/xray/error.log".to_owned());
    update_log_settings(
        &mut config,
        UpdateLogSettingsRequest { settings },
    )
    .expect("update");

    let after = log_config_view(config.sections().log());
    assert_eq!(after.access, XrayLogDestination::Disabled);
    assert_eq!(
        after.error,
        XrayLogDestination::File {
            path: "/var/log/xray/error.log".to_owned()
        }
    );
}

#[test]
fn add_wireguard_outbound_unique_tag() {
    let mut config = single_file_editable(
        r#"{"outbounds":[{"tag":"direct","protocol":"freedom","settings":{}}]}"#,
    );
    let outbound = serde_json::json!({
        "tag": "warp",
        "protocol": "wireguard",
        "settings": {
            "secretKey": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
            "address": ["172.16.0.2/32"],
            "peers": [{
                "publicKey": "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=",
                "endpoint": "engage.cloudflareclient.com:2408"
            }]
        }
    });
    let outcome = add_outbound(
        &mut config,
        AddOutboundRequest {
            outbound,
            preferred_source_file: None,
        },
    )
    .expect("add");
    assert_eq!(outcome.source_file, "/etc/xray/config.json");
    assert!(config.find_outbound_index_by_tag("warp").is_some());
    assert_eq!(config.sections().outbounds().len(), 2);
    // Routing untouched.
    assert!(config.sections().routing().is_none());
}

#[test]
fn add_outbound_tag_conflict() {
    let mut config = single_file_editable(
        r#"{"outbounds":[{"tag":"warp","protocol":"freedom","settings":{}}]}"#,
    );
    let outbound = serde_json::json!({
        "tag": "warp",
        "protocol": "wireguard",
        "settings": {
            "secretKey": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
            "address": ["172.16.0.2/32"],
            "peers": [{
                "publicKey": "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=",
                "endpoint": "engage.cloudflareclient.com:2408"
            }]
        }
    });
    let error = add_outbound(
        &mut config,
        AddOutboundRequest {
            outbound,
            preferred_source_file: None,
        },
    )
    .unwrap_err();
    assert_eq!(error.kind(), ConfigModifyErrorKind::OutboundTagConflict);
}

#[test]
fn replace_and_remove_wireguard_outbound() {
    let mut config = single_file_editable(
        r#"{
            "outbounds":[{
                "tag":"warp",
                "protocol":"wireguard",
                "settings":{
                    "secretKey":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
                    "address":["172.16.0.2/32"],
                    "peers":[{"publicKey":"bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=","endpoint":"engage.cloudflareclient.com:2408"}]
                }
            }]
        }"#,
    );
    let replacement = serde_json::json!({
        "tag": "warp",
        "protocol": "wireguard",
        "settings": {
            "secretKey": "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=",
            "address": ["172.16.0.2/32", "2606:4700:110::1/128"],
            "peers": [{
                "publicKey": "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=",
                "endpoint": "engage.cloudflareclient.com:2408"
            }]
        }
    });
    replace_outbound(
        &mut config,
        ReplaceOutboundRequest {
            tag: "warp".to_owned(),
            outbound: replacement,
        },
    )
    .expect("replace");
    let idx = config.find_outbound_index_by_tag("warp").unwrap();
    let addresses = config.sections().outbounds()[idx]
        .value()
        .pointer("/settings/address")
        .and_then(|v| v.as_array())
        .map(|a| a.len())
        .unwrap_or(0);
    assert_eq!(addresses, 2);

    remove_outbound(
        &mut config,
        RemoveOutboundRequest {
            tag: "warp".to_owned(),
        },
    )
    .expect("remove");
    assert!(config.find_outbound_index_by_tag("warp").is_none());
}

#[test]
fn add_freedom_outbound_shell_writes_settings() {
    use super::outbound_edit::OutboundGeneral;
    use super::outbound_protocol::{FragmentDraft, NoiseDraft, OutboundSettingsDraft};

    let mut config = single_file_editable(r#"{"outbounds":[]}"#);
    let outcome = add_outbound_shell(
        &mut config,
        AddOutboundShellRequest {
            general: OutboundGeneral {
                tag: Some("direct".to_owned()),
                send_through: Some("0.0.0.0".to_owned()),
            },
            settings: OutboundSettingsDraft::Freedom {
                domain_strategy: "UseIP".to_owned(),
                redirect: "127.0.0.1:3366".to_owned(),
                user_level: 1,
                fragment: Some(FragmentDraft {
                    packets: "tlshello".to_owned(),
                    length: "100-200".to_owned(),
                    interval: "10-20".to_owned(),
                    extras: Default::default(),
                }),
                noises: vec![NoiseDraft {
                    kind: "rand".to_owned(),
                    packet: "10-20".to_owned(),
                    delay: "10-16".to_owned(),
                    extras: Default::default(),
                }],
            },
            preferred_source_file: None,
        },
    )
    .expect("add freedom outbound");
    assert_eq!(outcome.source_file, "/etc/xray/config.json");
    let idx = config.find_outbound_index_by_tag("direct").expect("found");
    let outbound = config.sections().outbounds()[idx].value();
    assert_eq!(outbound["protocol"], "freedom");
    assert_eq!(outbound["sendThrough"], "0.0.0.0");
    assert_eq!(outbound["settings"]["domainStrategy"], "UseIP");
    assert_eq!(outbound["settings"]["redirect"], "127.0.0.1:3366");
    assert_eq!(outbound["settings"]["userLevel"], 1);
    assert_eq!(outbound["settings"]["fragment"]["packets"], "tlshello");
    assert_eq!(outbound["settings"]["noises"][0]["type"], "rand");
    // Routing untouched.
    assert!(config.sections().routing().is_none());
}

#[test]
fn update_freedom_outbound_shell_edits_settings_and_preserves_unrelated_fields() {
    use super::outbound_edit::{OutboundGeneral, OutboundRef};
    use super::outbound_protocol::OutboundSettingsDraft;

    let mut config = single_file_editable(
        r#"{
            "outbounds":[{
                "tag":"direct",
                "protocol":"freedom",
                "settings":{"domainStrategy":"AsIs","futureField":"keep"},
                "mux":{"enabled":true}
            }]
        }"#,
    );
    let index = config.find_outbound_index_by_tag("direct").expect("found");
    let expected_fingerprint = config
        .outbound_object_fingerprint(index)
        .expect("fingerprint");

    update_outbound_shell(
        &mut config,
        UpdateOutboundShellRequest {
            outbound_ref: OutboundRef {
                outbound_index: index,
                expected_fingerprint,
            },
            general: OutboundGeneral {
                tag: Some("direct".to_owned()),
                send_through: None,
            },
            settings: OutboundSettingsDraft::Freedom {
                domain_strategy: "UseIPv4".to_owned(),
                redirect: String::new(),
                user_level: 0,
                fragment: None,
                noises: Vec::new(),
            },
        },
    )
    .expect("update freedom outbound shell");

    let outbound = config.sections().outbounds()[index].value();
    assert_eq!(outbound["settings"]["domainStrategy"], "UseIPv4");
    assert_eq!(outbound["settings"]["futureField"], "keep");
    assert_eq!(outbound["mux"]["enabled"], true);
}

#[test]
fn update_freedom_outbound_shell_fingerprint_mismatch_rejected() {
    use super::outbound_edit::{OutboundGeneral, OutboundRef};
    use super::outbound_protocol::OutboundSettingsDraft;

    let mut config = single_file_editable(
        r#"{"outbounds":[{"tag":"direct","protocol":"freedom","settings":{}}]}"#,
    );
    let error = update_outbound_shell(
        &mut config,
        UpdateOutboundShellRequest {
            outbound_ref: OutboundRef {
                outbound_index: 0,
                expected_fingerprint: "stale".to_owned(),
            },
            general: OutboundGeneral {
                tag: Some("direct".to_owned()),
                send_through: None,
            },
            settings: OutboundSettingsDraft::freedom_default(),
        },
    )
    .unwrap_err();
    assert_eq!(error.kind(), ConfigModifyErrorKind::FingerprintMismatch);
}

#[test]
fn update_freedom_outbound_shell_rejects_tag_rename() {
    use super::outbound_edit::{OutboundGeneral, OutboundRef};
    use super::outbound_protocol::OutboundSettingsDraft;

    let mut config = single_file_editable(
        r#"{"outbounds":[{"tag":"direct","protocol":"freedom","settings":{}}]}"#,
    );
    let expected_fingerprint = config.outbound_object_fingerprint(0).expect("fingerprint");
    let error = update_outbound_shell(
        &mut config,
        UpdateOutboundShellRequest {
            outbound_ref: OutboundRef {
                outbound_index: 0,
                expected_fingerprint,
            },
            general: OutboundGeneral {
                tag: Some("direct-renamed".to_owned()),
                send_through: None,
            },
            settings: OutboundSettingsDraft::freedom_default(),
        },
    )
    .unwrap_err();
    assert_eq!(error.kind(), ConfigModifyErrorKind::ValidationFailed);
}

#[test]
fn add_blackhole_outbound_shell_writes_settings() {
    use super::outbound_edit::OutboundGeneral;
    use super::outbound_protocol::OutboundSettingsDraft;

    let mut config = single_file_editable(r#"{"outbounds":[]}"#);
    let outcome = add_outbound_shell(
        &mut config,
        AddOutboundShellRequest {
            general: OutboundGeneral {
                tag: Some("block".to_owned()),
                send_through: None,
            },
            settings: OutboundSettingsDraft::Blackhole {
                response_type: "http".to_owned(),
                response_extras: Default::default(),
            },
            preferred_source_file: None,
        },
    )
    .expect("add blackhole outbound");
    assert_eq!(outcome.source_file, "/etc/xray/config.json");
    let idx = config.find_outbound_index_by_tag("block").expect("found");
    let outbound = config.sections().outbounds()[idx].value();
    assert_eq!(outbound["protocol"], "blackhole");
    assert_eq!(outbound["settings"]["response"]["type"], "http");
}

#[test]
fn update_blackhole_outbound_shell_edits_settings_and_preserves_unrelated_fields() {
    use super::outbound_edit::{OutboundGeneral, OutboundRef};
    use super::outbound_protocol::OutboundSettingsDraft;

    let mut config = single_file_editable(
        r#"{
            "outbounds":[{
                "tag":"block",
                "protocol":"blackhole",
                "settings":{"response":{"type":"none"},"futureField":"keep"},
                "mux":{"enabled":true}
            }]
        }"#,
    );
    let index = config.find_outbound_index_by_tag("block").expect("found");
    let expected_fingerprint = config
        .outbound_object_fingerprint(index)
        .expect("fingerprint");

    update_outbound_shell(
        &mut config,
        UpdateOutboundShellRequest {
            outbound_ref: OutboundRef {
                outbound_index: index,
                expected_fingerprint,
            },
            general: OutboundGeneral {
                tag: Some("block".to_owned()),
                send_through: None,
            },
            settings: OutboundSettingsDraft::Blackhole {
                response_type: "http".to_owned(),
                response_extras: Default::default(),
            },
        },
    )
    .expect("update blackhole outbound shell");

    let outbound = config.sections().outbounds()[index].value();
    assert_eq!(outbound["settings"]["response"]["type"], "http");
    assert_eq!(outbound["settings"]["futureField"], "keep");
    assert_eq!(outbound["mux"]["enabled"], true);
}

#[test]
fn add_dns_outbound_shell_writes_settings() {
    use super::outbound_edit::OutboundGeneral;
    use super::outbound_protocol::{DnsRuleDraft, OutboundSettingsDraft};

    let mut config = single_file_editable(r#"{"outbounds":[]}"#);
    let outcome = add_outbound_shell(
        &mut config,
        AddOutboundShellRequest {
            general: OutboundGeneral {
                tag: Some("dns-out".to_owned()),
                send_through: None,
            },
            settings: OutboundSettingsDraft::Dns {
                rewrite_network: "udp".to_owned(),
                rewrite_address: "1.1.1.1".to_owned(),
                rewrite_port: "53".to_owned(),
                user_level: 1,
                rules: vec![DnsRuleDraft {
                    action: "return".to_owned(),
                    q_type: String::new(),
                    r_code: 5,
                    domain: vec!["domain:example.com".to_owned()],
                    extras: Default::default(),
                }],
            },
            preferred_source_file: None,
        },
    )
    .expect("add dns outbound");
    assert_eq!(outcome.source_file, "/etc/xray/config.json");
    let idx = config.find_outbound_index_by_tag("dns-out").expect("found");
    let outbound = config.sections().outbounds()[idx].value();
    assert_eq!(outbound["protocol"], "dns");
    assert_eq!(outbound["settings"]["rewriteNetwork"], "udp");
    assert_eq!(outbound["settings"]["rewriteAddress"], "1.1.1.1");
    assert_eq!(outbound["settings"]["rewritePort"], 53);
    assert_eq!(outbound["settings"]["userLevel"], 1);
    assert_eq!(outbound["settings"]["rules"][0]["action"], "return");
    assert_eq!(outbound["settings"]["rules"][0]["rCode"], 5);
    // Routing untouched.
    assert!(config.sections().routing().is_none());
}

#[test]
fn update_dns_outbound_shell_edits_settings_and_preserves_unrelated_fields() {
    use super::outbound_edit::{OutboundGeneral, OutboundRef};
    use super::outbound_protocol::OutboundSettingsDraft;

    let mut config = single_file_editable(
        r#"{
            "outbounds":[{
                "tag":"dns-out",
                "protocol":"dns",
                "settings":{"rewriteNetwork":"tcp","futureField":"keep"},
                "mux":{"enabled":true}
            }]
        }"#,
    );
    let index = config.find_outbound_index_by_tag("dns-out").expect("found");
    let expected_fingerprint = config
        .outbound_object_fingerprint(index)
        .expect("fingerprint");

    update_outbound_shell(
        &mut config,
        UpdateOutboundShellRequest {
            outbound_ref: OutboundRef {
                outbound_index: index,
                expected_fingerprint,
            },
            general: OutboundGeneral {
                tag: Some("dns-out".to_owned()),
                send_through: None,
            },
            settings: OutboundSettingsDraft::Dns {
                rewrite_network: "udp".to_owned(),
                rewrite_address: String::new(),
                rewrite_port: String::new(),
                user_level: 0,
                rules: Vec::new(),
            },
        },
    )
    .expect("update dns outbound shell");

    let outbound = config.sections().outbounds()[index].value();
    assert_eq!(outbound["settings"]["rewriteNetwork"], "udp");
    assert_eq!(outbound["settings"]["futureField"], "keep");
    assert_eq!(outbound["mux"]["enabled"], true);
}

#[test]
fn update_dns_outbound_shell_fingerprint_mismatch_rejected() {
    use super::outbound_edit::{OutboundGeneral, OutboundRef};
    use super::outbound_protocol::OutboundSettingsDraft;

    let mut config =
        single_file_editable(r#"{"outbounds":[{"tag":"dns-out","protocol":"dns","settings":{}}]}"#);
    let error = update_outbound_shell(
        &mut config,
        UpdateOutboundShellRequest {
            outbound_ref: OutboundRef {
                outbound_index: 0,
                expected_fingerprint: "stale".to_owned(),
            },
            general: OutboundGeneral {
                tag: Some("dns-out".to_owned()),
                send_through: None,
            },
            settings: OutboundSettingsDraft::dns_default(),
        },
    )
    .unwrap_err();
    assert_eq!(error.kind(), ConfigModifyErrorKind::FingerprintMismatch);
}

#[test]
fn update_dns_outbound_shell_rejects_tag_rename() {
    use super::outbound_edit::{OutboundGeneral, OutboundRef};
    use super::outbound_protocol::OutboundSettingsDraft;

    let mut config =
        single_file_editable(r#"{"outbounds":[{"tag":"dns-out","protocol":"dns","settings":{}}]}"#);
    let expected_fingerprint = config.outbound_object_fingerprint(0).expect("fingerprint");
    let error = update_outbound_shell(
        &mut config,
        UpdateOutboundShellRequest {
            outbound_ref: OutboundRef {
                outbound_index: 0,
                expected_fingerprint,
            },
            general: OutboundGeneral {
                tag: Some("dns-out-renamed".to_owned()),
                send_through: None,
            },
            settings: OutboundSettingsDraft::dns_default(),
        },
    )
    .unwrap_err();
    assert_eq!(error.kind(), ConfigModifyErrorKind::ValidationFailed);
}

#[test]
fn lake1_ambiguous_clients_and_users_rejected() {
    let mut config = single_file_editable(
        r#"{
            "inbounds":[{
                "protocol":"vless",
                "settings":{
                    "clients":[{"id":"u1","email":"a@example.com"}],
                    "users":[{"id":"u2","email":"b@example.com"}],
                    "decryption":"none"
                }
            }]
        }"#,
    );

    let error = add_user(
        &mut config,
        AddUserRequest {
            inbound_index: 0,
            email: "c@example.com".to_owned(),
            id: None,
            flow: None,
            level: 0,
        },
    )
    .expect_err("ambiguous");
    assert_eq!(error.kind(), ConfigModifyErrorKind::AmbiguousClientsArray);
}

#[test]
fn lake1_fingerprint_mismatch_rejects_update() {
    let mut config = single_file_editable(
        r#"{
            "inbounds":[{
                "protocol":"vless",
                "settings":{
                    "clients":[{"id":"u1","email":"a@example.com","futureField":"keep"}],
                    "decryption":"none"
                }
            }]
        }"#,
    );

    let error = update_user(
        &mut config,
        UpdateUserRequest {
            inbound_index: 0,
            client_index: 0,
            email: "b@example.com".to_owned(),
            flow: None,
            level: 0,
            expected_fingerprint: Some("deadbeef".to_owned()),
        },
    )
    .expect_err("stale fingerprint");
    assert_eq!(error.kind(), ConfigModifyErrorKind::FingerprintMismatch);

    let client =
        &config.file_roots()["/etc/xray/config.json"]["inbounds"][0]["settings"]["clients"][0];
    assert_eq!(client["email"], "a@example.com");
    assert_eq!(client["futureField"], "keep");
}

#[test]
fn lake1_fingerprint_match_allows_update() {
    let mut config = single_file_editable(
        r#"{
            "inbounds":[{
                "protocol":"vless",
                "settings":{
                    "clients":[{"id":"u1","email":"a@example.com"}],
                    "decryption":"none"
                }
            }]
        }"#,
    );
    let fingerprint = config
        .client_fingerprint(0, 0)
        .expect("fingerprint");

    update_user(
        &mut config,
        UpdateUserRequest {
            inbound_index: 0,
            client_index: 0,
            email: "b@example.com".to_owned(),
            flow: None,
            level: 0,
            expected_fingerprint: Some(fingerprint),
        },
    )
    .expect("update");

    let client =
        &config.file_roots()["/etc/xray/config.json"]["inbounds"][0]["settings"]["clients"][0];
    assert_eq!(client["email"], "b@example.com");
}

#[test]
fn lake1_level_round_trip_on_add_and_update() {
    let mut config = single_file_editable(
        r#"{
            "inbounds":[{
                "protocol":"vless",
                "settings":{"clients":[],"decryption":"none"}
            }]
        }"#,
    );

    add_user(
        &mut config,
        AddUserRequest {
            inbound_index: 0,
            email: "lvl@example.com".to_owned(),
            id: Some("11111111-1111-4111-8111-111111111111".to_owned()),
            flow: None,
            level: 2,
        },
    )
    .expect("add");

    let client =
        &config.file_roots()["/etc/xray/config.json"]["inbounds"][0]["settings"]["clients"][0];
    assert_eq!(client["level"], 2);

    update_user(
        &mut config,
        UpdateUserRequest {
            inbound_index: 0,
            client_index: 0,
            email: "lvl@example.com".to_owned(),
            flow: None,
            level: 5,
            expected_fingerprint: None,
        },
    )
    .expect("update");

    let client =
        &config.file_roots()["/etc/xray/config.json"]["inbounds"][0]["settings"]["clients"][0];
    assert_eq!(client["level"], 5);
}

#[test]
fn lake1_users_array_key_preserved() {
    let mut config = single_file_editable(
        r#"{
            "inbounds":[{
                "protocol":"vless",
                "settings":{
                    "users":[{"id":"u1","email":"a@example.com"}],
                    "decryption":"none"
                }
            }]
        }"#,
    );

    add_user(
        &mut config,
        AddUserRequest {
            inbound_index: 0,
            email: "b@example.com".to_owned(),
            id: Some("u2".to_owned()),
            flow: None,
            level: 0,
        },
    )
    .expect("add");

    let settings = &config.file_roots()["/etc/xray/config.json"]["inbounds"][0]["settings"];
    assert!(settings.get("clients").is_none());
    assert_eq!(settings["users"].as_array().map(Vec::len), Some(2));
    assert_eq!(settings["users"][1]["email"], "b@example.com");
}

#[test]
fn ib_l1_trojan_client_add_strips_flow() {
    use super::modify::{AddInboundClientRequest, add_inbound_client};
    use crate::xray::secret::SecretString;

    let mut config = single_file_editable(
        r#"{
            "inbounds":[{
                "protocol":"trojan",
                "settings":{"clients":[{"password":"secret","email":"t@example.com"}]}
            }]
        }"#,
    );

    add_inbound_client(
        &mut config,
        AddInboundClientRequest::Trojan {
            inbound_index: 0,
            email: "x@example.com".to_owned(),
            password: SecretString::new("new-pass"),
            level: 0,
        },
    )
    .expect("trojan add enabled");

    let clients = &config.file_roots()["/etc/xray/config.json"]["inbounds"][0]["settings"]["clients"];
    assert_eq!(clients.as_array().map(Vec::len), Some(2));
    assert_eq!(clients[1]["email"], "x@example.com");
    assert_eq!(clients[1]["password"], "new-pass");
    assert!(clients[1].get("flow").is_none());
}

fn shell_ref(config: &EditableXrayConfig, inbound_index: usize) -> InboundRef {
    let location = config.locate_inbound(inbound_index).expect("locate");
    let protocol = config.sections().inbounds()[inbound_index]
        .value()
        .get("protocol")
        .and_then(Value::as_str)
        .and_then(InboundClientProtocol::from_wire)
        .expect("tier-2 protocol");
    let expected_fingerprint = config
        .inbound_object_fingerprint(inbound_index)
        .expect("fingerprint");
    InboundRef {
        location,
        protocol,
        expected_fingerprint,
    }
}

#[test]
fn shell_general_preserves_clients_reality_and_custom_fields() {
    let mut config = single_file_editable(
        r#"{
            "inbounds":[{
                "tag":"vless-in",
                "protocol":"vless",
                "listen":"0.0.0.0",
                "port":443,
                "customField":"keep-me",
                "settings":{"clients":[{"id":"u1","email":"a@example.com"}],"decryption":"none"},
                "streamSettings":{
                    "network":"tcp",
                    "security":"reality",
                    "realitySettings":{"serverNames":["example.com"],"privateKey":"secret"}
                }
            }]
        }"#,
    );
    let inbound_ref = shell_ref(&config, 0);

    update_inbound_general(
        &mut config,
        UpdateInboundGeneralRequest {
            inbound_ref,
            general: InboundGeneral {
                tag: Some("vless-renamed".to_owned()),
                listen: Some("127.0.0.1".to_owned()),
                port: Some(8443),
            },
        },
    )
    .expect("general update");

    let inbound = &config.file_roots()["/etc/xray/config.json"]["inbounds"][0];
    assert_eq!(inbound["tag"], "vless-renamed");
    assert_eq!(inbound["listen"], "127.0.0.1");
    assert_eq!(inbound["port"], 8443);
    assert_eq!(inbound["customField"], "keep-me");
    assert_eq!(inbound["settings"]["clients"][0]["id"], "u1");
    assert_eq!(
        inbound["streamSettings"]["realitySettings"]["privateKey"],
        "secret"
    );
    assert_eq!(
        inbound["streamSettings"]["realitySettings"]["serverNames"][0],
        "example.com"
    );
}

#[test]
fn shell_general_empty_tag_omits_key() {
    let mut config = single_file_editable(
        r#"{
            "inbounds":[{
                "tag":"old",
                "protocol":"vless",
                "port":443,
                "settings":{"clients":[],"decryption":"none"}
            }]
        }"#,
    );
    let inbound_ref = shell_ref(&config, 0);
    update_inbound_general(
        &mut config,
        UpdateInboundGeneralRequest {
            inbound_ref,
            general: InboundGeneral {
                tag: Some("   ".to_owned()),
                listen: None,
                port: Some(443),
            },
        },
    )
    .expect("update");
    let inbound = &config.file_roots()["/etc/xray/config.json"]["inbounds"][0];
    assert!(inbound.get("tag").is_none());
}

#[test]
fn shell_general_coerces_decimal_string_port_to_number() {
    let mut config = single_file_editable(
        r#"{
            "inbounds":[{
                "protocol":"vless",
                "port":"8443",
                "settings":{"clients":[],"decryption":"none"}
            }]
        }"#,
    );
    let inbound_ref = shell_ref(&config, 0);
    update_inbound_general(
        &mut config,
        UpdateInboundGeneralRequest {
            inbound_ref,
            general: InboundGeneral {
                tag: None,
                listen: None,
                port: Some(8443),
            },
        },
    )
    .expect("update");
    let port = &config.file_roots()["/etc/xray/config.json"]["inbounds"][0]["port"];
    assert!(port.is_number());
    assert_eq!(port.as_u64(), Some(8443));
}

#[test]
fn shell_general_rejects_non_scalar_port() {
    let mut config = single_file_editable(
        r#"{
            "inbounds":[{
                "protocol":"vless",
                "port":[443,8443],
                "settings":{"clients":[],"decryption":"none"}
            }]
        }"#,
    );
    let inbound_ref = shell_ref(&config, 0);
    let error = update_inbound_general(
        &mut config,
        UpdateInboundGeneralRequest {
            inbound_ref,
            general: InboundGeneral {
                tag: None,
                listen: None,
                port: Some(443),
            },
        },
    )
    .expect_err("non-scalar");
    assert_eq!(error.kind(), ConfigModifyErrorKind::ValidationFailed);
}

#[test]
fn shell_general_rejects_invalid_listen() {
    let mut config = single_file_editable(
        r#"{
            "inbounds":[{
                "protocol":"vless",
                "settings":{"clients":[],"decryption":"none"}
            }]
        }"#,
    );
    let inbound_ref = shell_ref(&config, 0);
    let error = update_inbound_general(
        &mut config,
        UpdateInboundGeneralRequest {
            inbound_ref,
            general: InboundGeneral {
                tag: None,
                listen: Some(":::".to_owned()),
                port: None,
            },
        },
    )
    .expect_err("bad listen");
    assert_eq!(error.kind(), ConfigModifyErrorKind::ValidationFailed);
}

#[test]
fn shell_general_hard_blocks_duplicate_tag() {
    let mut config = single_file_editable(
        r#"{
            "inbounds":[
                {"tag":"a","protocol":"vless","settings":{"clients":[],"decryption":"none"}},
                {"tag":"b","protocol":"vless","settings":{"clients":[],"decryption":"none"}}
            ]
        }"#,
    );
    let inbound_ref = shell_ref(&config, 1);
    let error = update_inbound_general(
        &mut config,
        UpdateInboundGeneralRequest {
            inbound_ref,
            general: InboundGeneral {
                tag: Some("a".to_owned()),
                listen: None,
                port: None,
            },
        },
    )
    .expect_err("duplicate");
    assert_eq!(error.kind(), ConfigModifyErrorKind::ValidationFailed);
    assert!(error.message().contains("already in use"));
}

#[test]
fn shell_general_stale_fingerprint_aborts() {
    let mut config = single_file_editable(
        r#"{
            "inbounds":[{
                "protocol":"vless",
                "settings":{"clients":[],"decryption":"none"}
            }]
        }"#,
    );
    let mut inbound_ref = shell_ref(&config, 0);
    inbound_ref.expected_fingerprint = "deadbeef".to_owned();
    let error = update_inbound_general(
        &mut config,
        UpdateInboundGeneralRequest {
            inbound_ref,
            general: InboundGeneral {
                tag: Some("x".to_owned()),
                listen: None,
                port: None,
            },
        },
    )
    .expect_err("stale");
    assert_eq!(error.kind(), ConfigModifyErrorKind::FingerprintMismatch);
    assert!(error.message().contains("inbound"));
}

#[test]
fn shell_rejects_non_tier2_protocol() {
    let mut config = single_file_editable(
        r#"{
            "inbounds":[{
                "protocol":"vmess",
                "settings":{}
            }]
        }"#,
    );
    let location = config.locate_inbound(0).expect("locate");
    let error = update_inbound_general(
        &mut config,
        UpdateInboundGeneralRequest {
            inbound_ref: InboundRef {
                location,
                protocol: InboundClientProtocol::Vless,
                expected_fingerprint: "00".to_owned(),
            },
            general: InboundGeneral {
                tag: Some("ss".to_owned()),
                listen: None,
                port: None,
            },
        },
    )
    .expect_err("unsupported");
    assert_eq!(error.kind(), ConfigModifyErrorKind::UnsupportedInbound);
}

#[test]
fn shell_edit_works_despite_ambiguous_clients_array() {
    let mut config = single_file_editable(
        r#"{
            "inbounds":[{
                "tag":"ambiguous",
                "protocol":"vless",
                "settings":{
                    "clients":[{"id":"u1","email":"a@example.com"}],
                    "users":[{"id":"u2","email":"b@example.com"}],
                    "decryption":"none"
                }
            }]
        }"#,
    );
    let inbound_ref = shell_ref(&config, 0);
    update_inbound_general(
        &mut config,
        UpdateInboundGeneralRequest {
            inbound_ref,
            general: InboundGeneral {
                tag: Some("ambiguous-ok".to_owned()),
                listen: None,
                port: None,
            },
        },
    )
    .expect("shell must not hit AmbiguousClientsArray");
    assert_eq!(
        config.file_roots()["/etc/xray/config.json"]["inbounds"][0]["tag"],
        "ambiguous-ok"
    );
}

#[test]
fn shell_trojan_general_enabled() {
    let mut config = single_file_editable(
        r#"{
            "inbounds":[{
                "tag":"trojan-in",
                "protocol":"trojan",
                "port":443,
                "settings":{"clients":[{"password":"secret","email":"t@example.com"}]}
            }]
        }"#,
    );
    let inbound_ref = shell_ref(&config, 0);
    update_inbound_general(
        &mut config,
        UpdateInboundGeneralRequest {
            inbound_ref,
            general: InboundGeneral {
                tag: Some("trojan-renamed".to_owned()),
                listen: Some("0.0.0.0".to_owned()),
                port: Some(8443),
            },
        },
    )
    .expect("trojan shell");
    let inbound = &config.file_roots()["/etc/xray/config.json"]["inbounds"][0];
    assert_eq!(inbound["tag"], "trojan-renamed");
    assert_eq!(inbound["settings"]["clients"][0]["password"], "secret");
}

#[test]
fn shell_sniffing_absent_defaults_is_no_write() {
    let mut config = single_file_editable(
        r#"{
            "inbounds":[{
                "protocol":"vless",
                "settings":{"clients":[],"decryption":"none"}
            }]
        }"#,
    );
    let before = config.serialize_source_file("/etc/xray/config.json").unwrap();
    let inbound_ref = shell_ref(&config, 0);
    let (outcome, write) = update_inbound_sniffing(
        &mut config,
        UpdateInboundSniffingRequest {
            inbound_ref,
            sniffing: SniffingSettings::default(),
        },
    )
    .expect("no-write ok");
    assert_eq!(write, SniffingWriteOutcome::NoWrite);
    assert_eq!(outcome.serialized, before);
    assert!(
        config.file_roots()["/etc/xray/config.json"]["inbounds"][0]
            .get("sniffing")
            .is_none()
    );
}

#[test]
fn shell_sniffing_creates_minimal_object_when_enabled() {
    let mut config = single_file_editable(
        r#"{
            "inbounds":[{
                "protocol":"vless",
                "settings":{"clients":[],"decryption":"none"}
            }]
        }"#,
    );
    let inbound_ref = shell_ref(&config, 0);
    let (_, write) = update_inbound_sniffing(
        &mut config,
        UpdateInboundSniffingRequest {
            inbound_ref,
            sniffing: SniffingSettings {
                enabled: Some(true),
                dest_override: vec!["http".to_owned(), "tls".to_owned()],
                metadata_only: Some(false),
                route_only: Some(true),
                extras: Default::default(),
                unknown_dest_override: Vec::new(),
            },
        },
    )
    .expect("create");
    assert_eq!(write, SniffingWriteOutcome::Written);
    let sniffing = &config.file_roots()["/etc/xray/config.json"]["inbounds"][0]["sniffing"];
    assert_eq!(sniffing["enabled"], true);
    assert_eq!(sniffing["routeOnly"], true);
    assert_eq!(
        sniffing["destOverride"],
        serde_json::json!(["http", "tls"])
    );
}

#[test]
fn shell_sniffing_preserves_unknown_dest_and_extras() {
    let mut config = single_file_editable(
        r#"{
            "inbounds":[{
                "protocol":"vless",
                "settings":{"clients":[{"id":"u1"}],"decryption":"none"},
                "sniffing":{
                    "enabled":true,
                    "destOverride":["http","custom"],
                    "domainsExcluded":["example.com"]
                }
            }]
        }"#,
    );
    let inbound_ref = shell_ref(&config, 0);
    let mut sniffing = super::inbound_edit::parse_sniffing_settings(
        config.sections().inbounds()[0].value(),
    );
    assert_eq!(sniffing.dest_override, vec!["http".to_owned()]);
    assert_eq!(sniffing.unknown_dest_override, vec!["custom".to_owned()]);
    sniffing.dest_override = vec!["http".to_owned(), "tls".to_owned()];

    update_inbound_sniffing(
        &mut config,
        UpdateInboundSniffingRequest {
            inbound_ref,
            sniffing,
        },
    )
    .expect("patch");

    let sniffing = &config.file_roots()["/etc/xray/config.json"]["inbounds"][0]["sniffing"];
    assert_eq!(
        sniffing["destOverride"],
        serde_json::json!(["http", "tls", "custom"])
    );
    assert_eq!(sniffing["domainsExcluded"][0], "example.com");
    assert_eq!(
        config.file_roots()["/etc/xray/config.json"]["inbounds"][0]["settings"]["clients"][0]["id"],
        "u1"
    );
    assert_eq!(KNOWN_DEST_OVERRIDE[0], "http");
}

#[test]
fn shell_general_confdir_writes_only_owning_file() {
    let mut config = directory_editable(&[
        (
            "/etc/xray/01.json",
            r#"{"inbounds":[{"tag":"a","protocol":"vless","settings":{"clients":[],"decryption":"none"}}]}"#,
        ),
        (
            "/etc/xray/02.json",
            r#"{"inbounds":[{"tag":"b","protocol":"vless","port":443,"settings":{"clients":[],"decryption":"none"}}]}"#,
        ),
    ]);
    let before_a = config.serialize_source_file("/etc/xray/01.json").unwrap();
    let inbound_ref = shell_ref(&config, 1);
    let outcome = update_inbound_general(
        &mut config,
        UpdateInboundGeneralRequest {
            inbound_ref,
            general: InboundGeneral {
                tag: Some("b2".to_owned()),
                listen: None,
                port: Some(8443),
            },
        },
    )
    .expect("update");
    assert_eq!(outcome.source_file, "/etc/xray/02.json");
    assert_eq!(
        config.serialize_source_file("/etc/xray/01.json").unwrap(),
        before_a
    );
    assert_eq!(
        config.file_roots()["/etc/xray/02.json"]["inbounds"][0]["tag"],
        "b2"
    );
}

#[test]
fn shell_users_fingerprint_regression_still_works() {
    // CRITICAL: client fingerprint path must remain intact after shared json_value_fingerprint.
    let mut config = single_file_editable(
        r#"{
            "inbounds":[{
                "protocol":"vless",
                "settings":{
                    "clients":[{"id":"u1","email":"a@example.com","futureField":"keep"}],
                    "decryption":"none"
                }
            }]
        }"#,
    );
    let fingerprint = config.client_fingerprint(0, 0).expect("fp");
    update_user(
        &mut config,
        UpdateUserRequest {
            inbound_index: 0,
            client_index: 0,
            email: "b@example.com".to_owned(),
            flow: None,
            level: 0,
            expected_fingerprint: Some(fingerprint),
        },
    )
    .expect("update");
    let client =
        &config.file_roots()["/etc/xray/config.json"]["inbounds"][0]["settings"]["clients"][0];
    assert_eq!(client["email"], "b@example.com");
    assert_eq!(client["futureField"], "keep");
}

#[test]
fn ib_l1_add_vless_writes_default_stream() {
    use super::inbound_protocol::InboundProtocolDraft;
    use super::inbound_stream::InboundStreamDraft;
    use super::modify::{AddInboundRequest, add_inbound};

    let mut config = single_file_editable(r#"{"inbounds":[]}"#);
    add_inbound(
        &mut config,
        AddInboundRequest {
            protocol: InboundClientProtocol::Vless,
            general: InboundGeneral {
                tag: Some("vless-new".to_owned()),
                listen: Some("0.0.0.0".to_owned()),
                port: Some(443),
            },
            protocol_draft: InboundProtocolDraft::vless_default(),
            stream: InboundStreamDraft::default(),
            sniffing: SniffingSettings::default(),
            security: None,
            preferred_source_file: None,
        },
    )
    .expect("add vless");
    let inbound = &config.file_roots()["/etc/xray/config.json"]["inbounds"][0];
    assert_eq!(inbound["protocol"], "vless");
    assert_eq!(inbound["settings"]["decryption"], "none");
    assert_eq!(inbound["streamSettings"]["network"], "tcp");
    assert_eq!(inbound["settings"]["clients"].as_array().map(Vec::len), Some(0));
}

#[test]
fn ib_l1_add_trojan_requires_reality() {
    use super::inbound_protocol::InboundProtocolDraft;
    use super::inbound_stream::InboundStreamDraft;
    use super::modify::{AddInboundRequest, add_inbound};

    let mut config = single_file_editable(r#"{"inbounds":[]}"#);
    let err = add_inbound(
        &mut config,
        AddInboundRequest {
            protocol: InboundClientProtocol::Trojan,
            general: InboundGeneral {
                tag: Some("tr".to_owned()),
                listen: Some("0.0.0.0".to_owned()),
                port: Some(443),
            },
            protocol_draft: InboundProtocolDraft::trojan_default(),
            stream: InboundStreamDraft::default(),
            sniffing: SniffingSettings::default(),
            security: None,
            preferred_source_file: None,
        },
    )
    .expect_err("trojan without reality");
    assert_eq!(err.kind(), ConfigModifyErrorKind::ValidationFailed);
}

#[test]
fn ib_l1_add_trojan_with_reality_ok() {
    use super::inbound_protocol::InboundProtocolDraft;
    use super::inbound_security::{
        InboundSecurityDraft, InboundSecurityMode, RealitySettingsDraft,
    };
    use super::inbound_stream::InboundStreamDraft;
    use super::modify::{AddInboundRequest, add_inbound};

    let mut config = single_file_editable(r#"{"inbounds":[]}"#);
    add_inbound(
        &mut config,
        AddInboundRequest {
            protocol: InboundClientProtocol::Trojan,
            general: InboundGeneral {
                tag: Some("tr".to_owned()),
                listen: Some("0.0.0.0".to_owned()),
                port: Some(443),
            },
            protocol_draft: InboundProtocolDraft::trojan_default(),
            stream: InboundStreamDraft::default(),
            sniffing: SniffingSettings::default(),
            security: Some(InboundSecurityDraft {
                mode: InboundSecurityMode::Reality,
                reality: RealitySettingsDraft {
                    destination: "www.example.com:443".to_owned(),
                    private_key: "k".to_owned(),
                    server_names: vec!["www.example.com".to_owned()],
                    short_ids: vec!["abcd".to_owned()],
                    ..RealitySettingsDraft::default()
                },
                ..Default::default()
            }),
            preferred_source_file: None,
        },
    )
    .expect("add trojan");
    let inbound = &config.file_roots()["/etc/xray/config.json"]["inbounds"][0];
    assert_eq!(inbound["streamSettings"]["security"], "reality");
    assert_eq!(inbound["streamSettings"]["network"], "tcp");
    assert_eq!(
        inbound["streamSettings"]["realitySettings"]["privateKey"],
        "k"
    );
}

#[test]
fn ib_l1_shell_preserves_both_client_arrays_byte_identical() {
    use super::inbound_protocol::InboundProtocolDraft;
    use super::inbound_stream::parse_inbound_stream;
    use super::modify::{UpdateInboundShellRequest, update_inbound_shell};

    let mut config = single_file_editable(
        r#"{
            "inbounds":[{
                "tag":"ambiguous",
                "protocol":"vless",
                "settings":{
                    "clients":[{"id":"u1","email":"a@example.com","keep":true}],
                    "users":[{"id":"u2","email":"b@example.com","keep":1}],
                    "decryption":"none"
                }
            }]
        }"#,
    );
    let before_clients = config.file_roots()["/etc/xray/config.json"]["inbounds"][0]["settings"]
        ["clients"]
        .clone();
    let before_users = config.file_roots()["/etc/xray/config.json"]["inbounds"][0]["settings"]
        ["users"]
        .clone();
    let inbound_ref = shell_ref(&config, 0);
    let stream = parse_inbound_stream(
        &config.file_roots()["/etc/xray/config.json"]["inbounds"][0],
    );
    update_inbound_shell(
        &mut config,
        UpdateInboundShellRequest {
            inbound_ref,
            general: InboundGeneral {
                tag: Some("ambiguous-ok".to_owned()),
                listen: None,
                port: None,
            },
            protocol: InboundProtocolDraft::Vless {
                decryption: "none".to_owned(),
                fallbacks: Vec::new(),
            },
            stream,
            sniffing: SniffingSettings::default(),
            security: None,
        },
    )
    .expect("shell");
    let settings = &config.file_roots()["/etc/xray/config.json"]["inbounds"][0]["settings"];
    assert_eq!(settings["clients"], before_clients);
    assert_eq!(settings["users"], before_users);
    assert_eq!(
        config.file_roots()["/etc/xray/config.json"]["inbounds"][0]["tag"],
        "ambiguous-ok"
    );
}

#[test]
fn ib_l4_vless_shell_save_with_reality() {
    use super::inbound_protocol::InboundProtocolDraft;
    use super::inbound_security::{
        InboundSecurityDraft, InboundSecurityMode, RealitySettingsDraft,
    };
    use super::inbound_stream::parse_inbound_stream;
    use super::modify::{UpdateInboundShellRequest, update_inbound_shell};

    let mut config = single_file_editable(
        r#"{
            "inbounds":[{
                "tag":"vless-in",
                "protocol":"vless",
                "listen":"0.0.0.0",
                "port":443,
                "settings":{"clients":[{"id":"u1","email":"a@example.com"}],"decryption":"none"},
                "streamSettings":{"network":"tcp","security":"none"}
            }]
        }"#,
    );
    let inbound_ref = shell_ref(&config, 0);
    let stream = parse_inbound_stream(
        &config.file_roots()["/etc/xray/config.json"]["inbounds"][0],
    );
    update_inbound_shell(
        &mut config,
        UpdateInboundShellRequest {
            inbound_ref,
            general: InboundGeneral {
                tag: Some("vless-in".to_owned()),
                listen: Some("0.0.0.0".to_owned()),
                port: Some(443),
            },
            protocol: InboundProtocolDraft::Vless {
                decryption: "none".to_owned(),
                fallbacks: Vec::new(),
            },
            stream,
            sniffing: SniffingSettings::default(),
            security: Some(InboundSecurityDraft {
                mode: InboundSecurityMode::Reality,
                reality: RealitySettingsDraft {
                    destination: "www.example.com:443".to_owned(),
                    private_key: "vless-pk".to_owned(),
                    server_names: vec!["www.example.com".to_owned()],
                    short_ids: vec!["abcd".to_owned()],
                    ..RealitySettingsDraft::default()
                },
                ..Default::default()
            }),
        },
    )
    .expect("vless shell reality");
    let inbound = &config.file_roots()["/etc/xray/config.json"]["inbounds"][0];
    assert_eq!(inbound["streamSettings"]["security"], "reality");
    assert_eq!(
        inbound["streamSettings"]["realitySettings"]["privateKey"],
        "vless-pk"
    );
    assert_eq!(
        inbound["settings"]["clients"][0]["email"],
        "a@example.com"
    );
}

#[test]
fn finalmask_tcp_ok_with_tls_security() {
    use super::inbound_protocol::InboundProtocolDraft;
    use super::inbound_security::{CertificateDraft, InboundSecurityDraft, InboundSecurityMode, TlsSettingsDraft};
    use super::inbound_stream::{FinalMaskLayerDraft, InboundStreamDraft};
    use super::modify::{AddInboundRequest, add_inbound};

    let mut config = single_file_editable(r#"{"inbounds":[]}"#);
    let mut stream = InboundStreamDraft::default();
    stream.finalmask_tcp = vec![FinalMaskLayerDraft {
        layer_type: "fragment".to_owned(),
        settings: serde_json::json!({"packets": "tlshello"}),
    }];
    stream.write_finalmask_tcp = true;
    add_inbound(
        &mut config,
        AddInboundRequest {
            protocol: InboundClientProtocol::Vless,
            general: InboundGeneral {
                tag: Some("vless-fm".to_owned()),
                listen: Some("0.0.0.0".to_owned()),
                port: Some(443),
            },
            protocol_draft: InboundProtocolDraft::vless_default(),
            stream,
            sniffing: SniffingSettings::default(),
            security: Some(InboundSecurityDraft {
                mode: InboundSecurityMode::Tls,
                tls: TlsSettingsDraft {
                    certificates: vec![CertificateDraft {
                        certificate_file: "/c.pem".to_owned(),
                        key_file: "/k.pem".to_owned(),
                        ..Default::default()
                    }],
                    ..Default::default()
                },
                ..Default::default()
            }),
            preferred_source_file: None,
        },
    )
    .expect("vless add with tls + finalmask.tcp");
    let inbound = &config.file_roots()["/etc/xray/config.json"]["inbounds"][0];
    assert_eq!(
        inbound["streamSettings"]["finalmask"]["tcp"][0]["type"],
        "fragment"
    );
}

#[test]
fn finalmask_tcp_blocked_by_g4_with_reality_security() {
    use super::inbound_protocol::InboundProtocolDraft;
    use super::inbound_security::{InboundSecurityDraft, InboundSecurityMode, RealitySettingsDraft};
    use super::inbound_stream::{FinalMaskLayerDraft, InboundStreamDraft};
    use super::modify::{AddInboundRequest, add_inbound};

    let mut config = single_file_editable(r#"{"inbounds":[]}"#);
    let mut stream = InboundStreamDraft::default();
    stream.finalmask_tcp = vec![FinalMaskLayerDraft {
        layer_type: "fragment".to_owned(),
        settings: serde_json::json!({}),
    }];
    stream.write_finalmask_tcp = true;
    let err = add_inbound(
        &mut config,
        AddInboundRequest {
            protocol: InboundClientProtocol::Vless,
            general: InboundGeneral {
                tag: Some("vless-fm-reality".to_owned()),
                listen: Some("0.0.0.0".to_owned()),
                port: Some(443),
            },
            protocol_draft: InboundProtocolDraft::vless_default(),
            stream,
            sniffing: SniffingSettings::default(),
            security: Some(InboundSecurityDraft {
                mode: InboundSecurityMode::Reality,
                reality: RealitySettingsDraft {
                    destination: "www.example.com:443".to_owned(),
                    private_key: "k".to_owned(),
                    server_names: vec!["www.example.com".to_owned()],
                    short_ids: vec!["abcd".to_owned()],
                    ..RealitySettingsDraft::default()
                },
                ..Default::default()
            }),
            preferred_source_file: None,
        },
    )
    .expect_err("reality + finalmask.tcp must be blocked by G4");
    assert_eq!(err.kind(), ConfigModifyErrorKind::ValidationFailed);
    assert!(err.message().contains("finalmask"));
}

#[test]
fn ib_l4_vless_add_with_security_none_ok() {
    use super::inbound_protocol::InboundProtocolDraft;
    use super::inbound_security::{InboundSecurityDraft, InboundSecurityMode};
    use super::inbound_stream::InboundStreamDraft;
    use super::modify::{AddInboundRequest, add_inbound};

    let mut config = single_file_editable(r#"{"inbounds":[]}"#);
    add_inbound(
        &mut config,
        AddInboundRequest {
            protocol: InboundClientProtocol::Vless,
            general: InboundGeneral {
                tag: Some("vless-none".to_owned()),
                listen: Some("0.0.0.0".to_owned()),
                port: Some(443),
            },
            protocol_draft: InboundProtocolDraft::vless_default(),
            stream: InboundStreamDraft::default(),
            sniffing: SniffingSettings::default(),
            security: Some(InboundSecurityDraft {
                mode: InboundSecurityMode::None,
                ..Default::default()
            }),
            preferred_source_file: None,
        },
    )
    .expect("add vless none");
    let inbound = &config.file_roots()["/etc/xray/config.json"]["inbounds"][0];
    assert_eq!(inbound["protocol"], "vless");
    assert_eq!(inbound["streamSettings"]["network"], "tcp");
}

#[test]
fn ib_l4_g6_blocks_trojan_add_with_security_none() {
    use super::compatibility::CompatibilityGateId;
    use super::inbound_protocol::InboundProtocolDraft;
    use super::inbound_security::{InboundSecurityDraft, InboundSecurityMode};
    use super::inbound_stream::InboundStreamDraft;
    use super::modify::{AddInboundRequest, add_inbound};

    let mut config = single_file_editable(r#"{"inbounds":[]}"#);
    let err = add_inbound(
        &mut config,
        AddInboundRequest {
            protocol: InboundClientProtocol::Trojan,
            general: InboundGeneral {
                tag: Some("tr-none".to_owned()),
                listen: Some("0.0.0.0".to_owned()),
                port: Some(443),
            },
            protocol_draft: InboundProtocolDraft::trojan_default(),
            stream: InboundStreamDraft::default(),
            sniffing: SniffingSettings::default(),
            security: Some(InboundSecurityDraft {
                mode: InboundSecurityMode::None,
                ..Default::default()
            }),
            preferred_source_file: None,
        },
    )
    .expect_err("trojan none blocked");
    assert_eq!(err.kind(), ConfigModifyErrorKind::ValidationFailed);
    assert_eq!(err.detail(), CompatibilityGateId::G6.message());
}

#[test]
fn wave_c2_shell_save_requires_tls_alpn_for_fallbacks() {
    use super::inbound_fallbacks::{FallbackDest, FallbackObject};
    use super::inbound_protocol::InboundProtocolDraft;
    use super::inbound_security::{
        CertificateDraft, InboundSecurityDraft, InboundSecurityMode, TlsSettingsDraft,
    };
    use super::inbound_stream::InboundStreamDraft;
    use super::modify::{UpdateInboundShellRequest, update_inbound_shell};
    use super::modify_error::ConfigModifyErrorKind;

    let config_json = r#"{
            "inbounds":[{
                "tag":"vless-fb",
                "protocol":"vless",
                "settings":{"clients":[],"decryption":"none"},
                "streamSettings":{
                    "network":"tcp",
                    "security":"tls",
                    "tlsSettings":{
                        "certificates":[{"certificateFile":"/c.pem","keyFile":"/k.pem"}]
                    }
                }
            }]
        }"#;
    let protocol = InboundProtocolDraft::Vless {
        decryption: "none".to_owned(),
        fallbacks: vec![
            FallbackObject {
                dest: FallbackDest::Port(80),
                ..Default::default()
            },
            FallbackObject {
                dest: FallbackDest::TcpAddr("127.0.0.1:8080".into()),
                alpn: "h2".into(),
                path: "/".into(),
                xver: 1,
                ..Default::default()
            },
        ],
    };
    let file_cert = || CertificateDraft {
        certificate_file: "/c.pem".into(),
        key_file: "/k.pem".into(),
        ..Default::default()
    };

    {
        let mut config = single_file_editable(config_json);
        let inbound_ref = shell_ref(&config, 0);
        let err = update_inbound_shell(
            &mut config,
            UpdateInboundShellRequest {
                inbound_ref,
                general: InboundGeneral {
                    tag: Some("vless-fb".to_owned()),
                    listen: None,
                    port: None,
                },
                protocol: protocol.clone(),
                stream: InboundStreamDraft::default(),
                sniffing: SniffingSettings::default(),
                security: Some(InboundSecurityDraft {
                    mode: InboundSecurityMode::Tls,
                    tls: TlsSettingsDraft {
                        certificates: vec![file_cert()],
                        ..Default::default()
                    },
                    ..Default::default()
                }),
            },
        )
        .expect_err("empty alpn blocked");
        assert_eq!(err.kind(), ConfigModifyErrorKind::ValidationFailed);
        assert!(err.message().contains("alpn"));
    }

    let mut config = single_file_editable(config_json);
    let inbound_ref = shell_ref(&config, 0);
    update_inbound_shell(
        &mut config,
        UpdateInboundShellRequest {
            inbound_ref,
            general: InboundGeneral {
                tag: Some("vless-fb".to_owned()),
                listen: None,
                port: None,
            },
            protocol,
            stream: InboundStreamDraft::default(),
            sniffing: SniffingSettings::default(),
            security: Some(InboundSecurityDraft {
                mode: InboundSecurityMode::Tls,
                tls: TlsSettingsDraft {
                    certificates: vec![file_cert()],
                    alpn: vec!["h2".into(), "http/1.1".into()],
                    ..Default::default()
                },
                ..Default::default()
            }),
        },
    )
    .expect("shell with fallbacks + alpn");
    let inbound = &config.file_roots()["/etc/xray/config.json"]["inbounds"][0];
    assert_eq!(inbound["settings"]["fallbacks"].as_array().map(Vec::len), Some(2));
    assert_eq!(inbound["settings"]["fallbacks"][0]["dest"], 80);
    assert_eq!(inbound["settings"]["fallbacks"][1]["dest"], "127.0.0.1:8080");
    assert_eq!(inbound["settings"]["fallbacks"][1]["xver"], 1);
    assert_eq!(
        inbound["streamSettings"]["tlsSettings"]["alpn"],
        serde_json::json!(["h2", "http/1.1"])
    );
}

#[test]
fn wave_c2_shell_save_strips_fallbacks_on_ws() {
    use super::inbound_fallbacks::{FallbackDest, FallbackObject};
    use super::inbound_protocol::InboundProtocolDraft;
    use super::inbound_security::{
        CertificateDraft, InboundSecurityDraft, InboundSecurityMode, TlsSettingsDraft,
    };
    use super::inbound_stream::{InboundStreamDraft, StreamMethod, WsStreamSettings};
    use super::modify::{UpdateInboundShellRequest, update_inbound_shell};

    let mut config = single_file_editable(
        r#"{
            "inbounds":[{
                "tag":"vless-ws",
                "protocol":"vless",
                "settings":{
                    "clients":[],
                    "decryption":"none",
                    "fallbacks":[{"dest":80}]
                },
                "streamSettings":{
                    "network":"tcp",
                    "security":"tls",
                    "tlsSettings":{
                        "certificates":[{"certificateFile":"/c.pem","keyFile":"/k.pem"}]
                    }
                }
            }]
        }"#,
    );
    let inbound_ref = shell_ref(&config, 0);
    let mut stream = InboundStreamDraft::default();
    stream.method = Some(StreamMethod::Ws);
    stream.ws = WsStreamSettings::default();
    update_inbound_shell(
        &mut config,
        UpdateInboundShellRequest {
            inbound_ref,
            general: InboundGeneral {
                tag: Some("vless-ws".to_owned()),
                listen: None,
                port: None,
            },
            protocol: InboundProtocolDraft::Vless {
                decryption: "none".to_owned(),
                fallbacks: vec![FallbackObject {
                    dest: FallbackDest::Port(80),
                    ..Default::default()
                }],
            },
            stream,
            sniffing: SniffingSettings::default(),
            security: Some(InboundSecurityDraft {
                mode: InboundSecurityMode::Tls,
                tls: TlsSettingsDraft {
                    certificates: vec![CertificateDraft {
                        certificate_file: "/c.pem".into(),
                        key_file: "/k.pem".into(),
                        ..Default::default()
                    }],
                    ..Default::default()
                },
                ..Default::default()
            }),
        },
    )
    .expect("shell ws strips fallbacks");
    let inbound = &config.file_roots()["/etc/xray/config.json"]["inbounds"][0];
    assert!(inbound["settings"].get("fallbacks").is_none());
    assert_eq!(inbound["streamSettings"]["network"], "websocket");
}

#[test]
fn hysteria_client_add_appends_to_users_array() {
    use super::modify::{AddInboundClientRequest, add_inbound_client};
    use crate::xray::secret::SecretString;

    let mut config = single_file_editable(
        r#"{
            "inbounds":[{
                "protocol":"hysteria",
                "settings":{"version":2,"users":[{"auth":"existing","email":"a@example.com"}]}
            }]
        }"#,
    );

    add_inbound_client(
        &mut config,
        AddInboundClientRequest::Hysteria {
            inbound_index: 0,
            email: "b@example.com".to_owned(),
            auth: SecretString::new("new-auth"),
            level: 3,
        },
    )
    .expect("hysteria add");

    let settings = &config.file_roots()["/etc/xray/config.json"]["inbounds"][0]["settings"];
    assert!(settings.get("clients").is_none());
    let users = settings["users"].as_array().expect("users array");
    assert_eq!(users.len(), 2);
    assert_eq!(users[1]["auth"], "new-auth");
    assert_eq!(users[1]["email"], "b@example.com");
    assert_eq!(users[1]["level"], 3);
}

#[test]
fn hysteria_client_add_rejects_empty_auth() {
    use super::modify::{AddInboundClientRequest, add_inbound_client};
    use crate::xray::secret::SecretString;

    let mut config = single_file_editable(
        r#"{"inbounds":[{"protocol":"hysteria","settings":{"version":2,"users":[]}}]}"#,
    );

    let err = add_inbound_client(
        &mut config,
        AddInboundClientRequest::Hysteria {
            inbound_index: 0,
            email: "a@example.com".to_owned(),
            auth: SecretString::new("   "),
            level: 0,
        },
    )
    .expect_err("empty auth");
    assert_eq!(err.kind(), ConfigModifyErrorKind::ValidationFailed);
}

#[test]
fn hysteria_client_add_rejects_duplicate_email() {
    use super::modify::{AddInboundClientRequest, add_inbound_client};
    use crate::xray::secret::SecretString;

    let mut config = single_file_editable(
        r#"{
            "inbounds":[{
                "protocol":"hysteria",
                "settings":{"version":2,"users":[{"auth":"x","email":"dup@example.com"}]}
            }]
        }"#,
    );

    let err = add_inbound_client(
        &mut config,
        AddInboundClientRequest::Hysteria {
            inbound_index: 0,
            email: "dup@example.com".to_owned(),
            auth: SecretString::new("auth2"),
            level: 0,
        },
    )
    .expect_err("duplicate email");
    assert_eq!(err.kind(), ConfigModifyErrorKind::EmailConflict);
}

#[test]
fn hysteria_client_update_preserves_auth_on_preserve_draft() {
    use super::inbound_clients::SecretFieldDraft;
    use super::modify::{UpdateInboundClientRequest, update_inbound_client};

    let mut config = single_file_editable(
        r#"{
            "inbounds":[{
                "protocol":"hysteria",
                "settings":{"version":2,"users":[{"auth":"keep-me","email":"a@example.com","level":0}]}
            }]
        }"#,
    );

    update_inbound_client(
        &mut config,
        UpdateInboundClientRequest::Hysteria {
            inbound_index: 0,
            client_index: 0,
            email: "renamed@example.com".to_owned(),
            auth: SecretFieldDraft::Preserve,
            level: 2,
            expected_fingerprint: None,
        },
    )
    .expect("update");

    let user = &config.file_roots()["/etc/xray/config.json"]["inbounds"][0]["settings"]["users"][0];
    assert_eq!(user["auth"], "keep-me");
    assert_eq!(user["email"], "renamed@example.com");
    assert_eq!(user["level"], 2);
}

#[test]
fn hysteria_client_update_replaces_auth() {
    use super::inbound_clients::SecretFieldDraft;
    use super::modify::{UpdateInboundClientRequest, update_inbound_client};
    use crate::xray::secret::SecretString;

    let mut config = single_file_editable(
        r#"{
            "inbounds":[{
                "protocol":"hysteria",
                "settings":{"version":2,"users":[{"auth":"old","email":"a@example.com"}]}
            }]
        }"#,
    );

    update_inbound_client(
        &mut config,
        UpdateInboundClientRequest::Hysteria {
            inbound_index: 0,
            client_index: 0,
            email: "a@example.com".to_owned(),
            auth: SecretFieldDraft::Replace(SecretString::new("new-auth")),
            level: 0,
            expected_fingerprint: None,
        },
    )
    .expect("update");

    let user = &config.file_roots()["/etc/xray/config.json"]["inbounds"][0]["settings"]["users"][0];
    assert_eq!(user["auth"], "new-auth");
}

#[test]
fn hysteria_client_delete_by_index() {
    use super::modify::{DeleteUserRequest, delete_user};

    let mut config = single_file_editable(
        r#"{
            "inbounds":[{
                "protocol":"hysteria",
                "settings":{"version":2,"users":[
                    {"auth":"a","email":"a@example.com"},
                    {"auth":"b","email":"b@example.com"}
                ]}
            }]
        }"#,
    );

    delete_user(
        &mut config,
        DeleteUserRequest {
            inbound_index: 0,
            client_index: 0,
            expected_fingerprint: None,
        },
    )
    .expect("delete");

    let users = &config.file_roots()["/etc/xray/config.json"]["inbounds"][0]["settings"]["users"];
    assert_eq!(users.as_array().map(Vec::len), Some(1));
    assert_eq!(users[0]["email"], "b@example.com");
}

#[test]
fn delete_inbound_removes_from_merged_and_file_root() {
    use super::modify::{DeleteInboundRequest, delete_inbound};

    let mut config = single_file_editable(
        r#"{
            "inbounds":[
                {
                    "tag":"keep",
                    "protocol":"vless",
                    "port":443,
                    "settings":{"clients":[],"decryption":"none"}
                },
                {
                    "tag":"drop",
                    "protocol":"vless",
                    "port":8443,
                    "settings":{"clients":[],"decryption":"none"}
                }
            ]
        }"#,
    );
    let fingerprint = config
        .inbound_object_fingerprint(1)
        .expect("fingerprint");
    delete_inbound(
        &mut config,
        DeleteInboundRequest {
            inbound_index: 1,
            expected_fingerprint: Some(fingerprint),
        },
    )
    .expect("delete");
    assert_eq!(config.sections().inbounds().len(), 1);
    let tags: Vec<_> = config
        .file_roots()["/etc/xray/config.json"]["inbounds"]
        .as_array()
        .expect("array")
        .iter()
        .map(|v| v["tag"].as_str().unwrap().to_owned())
        .collect();
    assert_eq!(tags, vec!["keep".to_owned()]);
}

#[test]
fn delete_unsupported_inbound_ok() {
    use super::modify::{DeleteInboundRequest, delete_inbound};

    let mut config = single_file_editable(
        r#"{
            "inbounds":[{
                "tag":"vmess-in",
                "protocol":"vmess",
                "port":10086,
                "settings":{"clients":[]}
            }]
        }"#,
    );
    let fingerprint = config
        .inbound_object_fingerprint(0)
        .expect("fingerprint");
    delete_inbound(
        &mut config,
        DeleteInboundRequest {
            inbound_index: 0,
            expected_fingerprint: Some(fingerprint),
        },
    )
    .expect("delete vmess");
    assert!(config.sections().inbounds().is_empty());
}

#[test]
fn delete_inbound_blocked_by_routing_inbound_tag() {
    use super::modify::{DeleteInboundRequest, delete_inbound};

    let mut config = single_file_editable(
        r#"{
            "inbounds":[{
                "tag":"vmess-in",
                "protocol":"vmess",
                "port":10086,
                "settings":{"clients":[]}
            }],
            "routing":{
                "rules":[{"inboundTag":["vmess-in"],"outboundTag":"direct"}]
            }
        }"#,
    );
    let err = delete_inbound(
        &mut config,
        DeleteInboundRequest {
            inbound_index: 0,
            expected_fingerprint: None,
        },
    )
    .expect_err("blocked");
    assert_eq!(err.kind(), ConfigModifyErrorKind::ValidationFailed);
    assert!(err.message().contains("inboundTag"));
    assert_eq!(config.sections().inbounds().len(), 1);
}

#[test]
fn delete_outbound_ok_and_blocked_by_refs() {
    use super::modify::{DeleteOutboundRequest, delete_outbound};

    let mut blocked = single_file_editable(
        r#"{
            "outbounds":[
                {"tag":"direct","protocol":"freedom"},
                {"tag":"block","protocol":"blackhole"}
            ],
            "routing":{
                "rules":[{"outboundTag":"block","type":"field","protocol":["bittorrent"]}],
                "balancers":[{"tag":"b1","selector":["dir"]}]
            }
        }"#,
    );
    let err = delete_outbound(
        &mut blocked,
        DeleteOutboundRequest {
            outbound_index: 1,
            expected_fingerprint: None,
        },
    )
    .expect_err("block referenced");
    assert!(err.message().contains("outboundTag"));

    let err = delete_outbound(
        &mut blocked,
        DeleteOutboundRequest {
            outbound_index: 0,
            expected_fingerprint: None,
        },
    )
    .expect_err("direct matched by balancer prefix");
    assert!(err.message().contains("selector"));

    let mut clean = single_file_editable(
        r#"{
            "outbounds":[
                {"tag":"direct","protocol":"freedom"},
                {"tag":"block","protocol":"blackhole"}
            ]
        }"#,
    );
    delete_outbound(
        &mut clean,
        DeleteOutboundRequest {
            outbound_index: 1,
            expected_fingerprint: None,
        },
    )
    .expect("delete block");
    assert_eq!(clean.sections().outbounds().len(), 1);
}

#[test]
fn delete_inbound_fingerprint_mismatch() {
    use super::modify::{DeleteInboundRequest, delete_inbound};

    let mut config = single_file_editable(
        r#"{
            "inbounds":[{
                "tag":"vless-in",
                "protocol":"vless",
                "port":443,
                "settings":{"clients":[],"decryption":"none"}
            }]
        }"#,
    );
    let err = delete_inbound(
        &mut config,
        DeleteInboundRequest {
            inbound_index: 0,
            expected_fingerprint: Some("stale".to_owned()),
        },
    )
    .expect_err("mismatch");
    assert_eq!(err.kind(), ConfigModifyErrorKind::FingerprintMismatch);
    assert_eq!(config.sections().inbounds().len(), 1);
}

#[test]
fn duplicate_inbound_appends_unique_tag_copy() {
    use super::modify::{DuplicateInboundRequest, duplicate_inbound};

    let mut config = single_file_editable(
        r#"{
            "inbounds":[{
                "tag":"vless-in",
                "protocol":"vless",
                "port":443,
                "listen":"0.0.0.0",
                "settings":{"clients":[{"id":"a","email":"a@example.com"}],"decryption":"none"},
                "streamSettings":{"network":"tcp","security":"none"}
            }]
        }"#,
    );
    duplicate_inbound(
        &mut config,
        DuplicateInboundRequest { inbound_index: 0 },
    )
    .expect("duplicate");
    assert_eq!(config.sections().inbounds().len(), 2);
    let inbounds = config.file_roots()["/etc/xray/config.json"]["inbounds"]
        .as_array()
        .expect("array");
    assert_eq!(inbounds[0]["tag"], "vless-in");
    assert_eq!(inbounds[1]["tag"], "vless-in-copy");
    assert_eq!(inbounds[1]["port"], 443);
    assert_eq!(inbounds[1]["settings"]["clients"][0]["email"], "a@example.com");

    duplicate_inbound(
        &mut config,
        DuplicateInboundRequest { inbound_index: 0 },
    )
    .expect("second duplicate");
    let inbounds = config.file_roots()["/etc/xray/config.json"]["inbounds"]
        .as_array()
        .expect("array");
    assert_eq!(inbounds[2]["tag"], "vless-in-copy-2");
}

#[test]
fn tunnel_from_wire_only_not_dokodemo_door() {
    assert_eq!(
        InboundClientProtocol::from_wire("tunnel"),
        Some(InboundClientProtocol::Tunnel)
    );
    assert_eq!(InboundClientProtocol::from_wire("dokodemo-door"), None);
    assert!(InboundClientProtocol::Tunnel.shell_edit_enabled());
    assert!(!InboundClientProtocol::Tunnel.mutate_enabled());
}

#[test]
fn add_tunnel_inbound_writes_protocol_tunnel() {
    use super::inbound_protocol::InboundProtocolDraft;
    use super::inbound_stream::{InboundStreamDraft, StreamMethod};
    use super::modify::{AddInboundRequest, add_inbound};

    let mut config = single_file_editable(r#"{"inbounds":[]}"#);
    add_inbound(
        &mut config,
        AddInboundRequest {
            protocol: InboundClientProtocol::Tunnel,
            general: InboundGeneral {
                tag: Some("tun-in".to_owned()),
                listen: Some("0.0.0.0".to_owned()),
                port: Some(10085),
            },
            protocol_draft: InboundProtocolDraft::tunnel_default(),
            stream: InboundStreamDraft {
                method: Some(StreamMethod::Tcp),
                ..Default::default()
            },
            sniffing: SniffingSettings::default(),
            security: None,
            preferred_source_file: None,
        },
    )
    .expect("add tunnel");
    let inbound = &config.file_roots()["/etc/xray/config.json"]["inbounds"][0];
    assert_eq!(inbound["protocol"], "tunnel");
    assert_eq!(inbound["settings"]["allowedNetwork"], "tcp");
    assert_eq!(inbound["settings"]["rewriteAddress"], "localhost");
    assert_eq!(inbound["settings"]["followRedirect"], false);
    assert_eq!(inbound["settings"]["userLevel"], 0);
    assert!(inbound["settings"].get("clients").is_none());
    assert!(inbound["settings"].get("portMap").is_none());
    assert_eq!(inbound["streamSettings"]["network"], "tcp");
}

#[test]
fn tunnel_shell_save_preserves_stream_and_unknown_settings() {
    use super::inbound_protocol::InboundProtocolDraft;
    use super::inbound_stream::InboundStreamDraft;
    use super::modify::{UpdateInboundShellRequest, update_inbound_shell};

    let mut config = single_file_editable(
        r#"{
            "inbounds":[{
                "tag":"tun-in",
                "protocol":"tunnel",
                "port":10085,
                "listen":"127.0.0.1",
                "settings":{
                    "allowedNetwork":"tcp",
                    "rewriteAddress":"localhost",
                    "followRedirect":false,
                    "userLevel":0,
                    "futureField":"keep"
                },
                "streamSettings":{"network":"tcp","security":"none","sockopt":{"tproxy":"redirect"}}
            }]
        }"#,
    );
    let inbound_ref = shell_ref(&config, 0);
    update_inbound_shell(
        &mut config,
        UpdateInboundShellRequest {
            inbound_ref,
            general: InboundGeneral {
                tag: Some("tun-in".to_owned()),
                listen: Some("127.0.0.1".to_owned()),
                port: Some(10085),
            },
            protocol: InboundProtocolDraft::Tunnel {
                allowed_network: "tcp,udp".to_owned(),
                rewrite_address: "1.1.1.1".to_owned(),
                rewrite_port: Some(53),
                port_map: vec![("5555".to_owned(), ":8888".to_owned())],
                follow_redirect: true,
                user_level: 1,
            },
            stream: InboundStreamDraft::default(),
            sniffing: SniffingSettings::default(),
            security: None,
        },
    )
    .expect("shell save");
    let inbound = &config.file_roots()["/etc/xray/config.json"]["inbounds"][0];
    assert_eq!(inbound["settings"]["allowedNetwork"], "tcp,udp");
    assert_eq!(inbound["settings"]["rewriteAddress"], "1.1.1.1");
    assert_eq!(inbound["settings"]["rewritePort"], 53);
    assert_eq!(inbound["settings"]["followRedirect"], true);
    assert_eq!(inbound["settings"]["portMap"]["5555"], ":8888");
    assert_eq!(inbound["settings"]["futureField"], "keep");
    assert_eq!(inbound["streamSettings"]["sockopt"]["tproxy"], "redirect");
}

#[test]
fn tunnel_shell_save_edits_tproxy_and_preserves_other_stream_fields() {
    use super::inbound_protocol::InboundProtocolDraft;
    use super::inbound_stream::parse_inbound_stream;
    use super::modify::{UpdateInboundShellRequest, update_inbound_shell};

    let mut config = single_file_editable(
        r#"{
            "inbounds":[{
                "tag":"tun-in",
                "protocol":"tunnel",
                "port":10085,
                "listen":"127.0.0.1",
                "settings":{
                    "allowedNetwork":"tcp",
                    "rewriteAddress":"localhost",
                    "followRedirect":false,
                    "userLevel":0
                },
                "streamSettings":{
                    "network":"tcp",
                    "security":"none",
                    "sockopt":{"tproxy":"redirect","acceptProxyProtocol":true},
                    "futureStreamField":"keep"
                }
            }]
        }"#,
    );
    let inbound_ref = shell_ref(&config, 0);
    let mut stream = parse_inbound_stream(
        &config.file_roots()["/etc/xray/config.json"]["inbounds"][0],
    );
    assert!(stream.write_sockopt);
    stream.sockopt.tproxy = "tproxy".to_owned();
    update_inbound_shell(
        &mut config,
        UpdateInboundShellRequest {
            inbound_ref,
            general: InboundGeneral {
                tag: Some("tun-in".to_owned()),
                listen: Some("127.0.0.1".to_owned()),
                port: Some(10085),
            },
            protocol: InboundProtocolDraft::Tunnel {
                allowed_network: "tcp".to_owned(),
                rewrite_address: "localhost".to_owned(),
                rewrite_port: None,
                port_map: Vec::new(),
                follow_redirect: false,
                user_level: 0,
            },
            stream,
            sniffing: SniffingSettings::default(),
            security: None,
        },
    )
    .expect("tunnel tproxy shell save");
    let stream_settings =
        &config.file_roots()["/etc/xray/config.json"]["inbounds"][0]["streamSettings"];
    assert_eq!(stream_settings["sockopt"]["tproxy"], "tproxy");
    assert_eq!(stream_settings["sockopt"]["acceptProxyProtocol"], true);
    assert_eq!(stream_settings["network"], "tcp");
    assert_eq!(stream_settings["security"], "none");
    assert_eq!(stream_settings["futureStreamField"], "keep");
}

#[test]
fn sockopt_shell_save_edits_field_and_preserves_unknown_field() {
    use super::inbound_protocol::InboundProtocolDraft;
    use super::inbound_stream::parse_inbound_stream;
    use super::modify::{UpdateInboundShellRequest, update_inbound_shell};

    let mut config = single_file_editable(
        r#"{
            "inbounds":[{
                "tag":"vless-sockopt",
                "protocol":"vless",
                "listen":"0.0.0.0",
                "port":443,
                "settings":{"clients":[],"decryption":"none"},
                "streamSettings":{
                    "network":"tcp",
                    "security":"none",
                    "sockopt":{"tproxy":"off","acceptProxyProtocol":false,"futureField":"keep-me"}
                }
            }]
        }"#,
    );
    let inbound_ref = shell_ref(&config, 0);
    let mut stream = parse_inbound_stream(
        &config.file_roots()["/etc/xray/config.json"]["inbounds"][0],
    );
    assert!(stream.write_sockopt);
    stream.sockopt.tproxy = "redirect".to_owned();
    stream.sockopt.accept_proxy_protocol = true;
    update_inbound_shell(
        &mut config,
        UpdateInboundShellRequest {
            inbound_ref,
            general: InboundGeneral {
                tag: Some("vless-sockopt".to_owned()),
                listen: Some("0.0.0.0".to_owned()),
                port: Some(443),
            },
            protocol: InboundProtocolDraft::Vless {
                decryption: "none".to_owned(),
                fallbacks: Vec::new(),
            },
            stream,
            sniffing: SniffingSettings::default(),
            security: None,
        },
    )
    .expect("vless sockopt shell save");
    let sockopt = &config.file_roots()["/etc/xray/config.json"]["inbounds"][0]["streamSettings"]
        ["sockopt"];
    assert_eq!(sockopt["tproxy"], "redirect");
    assert_eq!(sockopt["acceptProxyProtocol"], true);
    assert_eq!(sockopt["futureField"], "keep-me");
}
