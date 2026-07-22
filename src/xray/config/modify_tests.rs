//! Tests for VLESS client add / update / delete and write-back safety.

use std::collections::BTreeMap;
use std::future;
use std::sync::{Arc, Mutex};

use feldjaeger_ssh::{ConnectionProfile, RemotePath, SshSession};
use serde_json::Value;

use super::XrayConfigParser;
use super::editable::EditableXrayConfig;
use super::modify::{
    AddUserRequest, DeleteUserRequest, UpdateUserRequest, add_user, delete_user,
    generate_client_uuid, update_user,
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
        },
    )
    .expect("add");

    let client =
        &config.file_roots()["/etc/xray/config.json"]["inbounds"][0]["settings"]["clients"][0];
    assert_eq!(client["flow"], "xtls-rprx-vision");
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

        fn exec(
            &self,
            _command: &feldjaeger_ssh::RemoteCommand,
        ) -> impl Future<Output = feldjaeger_ssh::SshResult<feldjaeger_ssh::ExecResult>> + Send
        {
            future::ready(Err(feldjaeger_ssh::SshError::new("unused")))
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
        },
    )
    .expect_err("conflict");
    assert_eq!(error.kind(), ConfigModifyErrorKind::EmailConflict);
}
