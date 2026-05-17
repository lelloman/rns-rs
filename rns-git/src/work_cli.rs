use std::fs;
use std::io::{self, Write};
use std::path::PathBuf;

use rns_core::msgpack::{self, Value};

use crate::client::{decode_status, SyncClient};
use crate::config::ClientConfig;
use crate::logging;
use crate::protocol;
use crate::util::{default_reticulum_dir, default_rngit_dir, parse_rns_url};
use crate::{Error, Result};

pub fn main<I>(args: I) -> Result<()>
where
    I: IntoIterator<Item = String>,
{
    let options = WorkOptions::parse(args)?;
    let (dest_hash, repository) = parse_rns_url(&options.remote)?;
    let rngit_dir = options.config_dir.unwrap_or_else(default_rngit_dir);
    let rns_dir = options.rns_config_dir.or_else(default_reticulum_dir);
    let (config, created) = ClientConfig::load_or_create(rngit_dir, rns_dir)?;
    logging::init_file_logger(&config.dir.join("client_log"), config.log_level)?;
    if created {
        return Err(Error::msg(format!(
            "created default config at {}; edit it and run again",
            config.dir.join("client_config").display()
        )));
    }

    let client = SyncClient::connect(config, dest_hash)?;
    let mut transport = NetWorkTransport { client, repository };
    run_work_command(&mut transport, &options.command, io::stdout())
}

trait WorkTransport {
    fn request(&mut self, data: Vec<u8>) -> Result<Vec<u8>>;
}

struct NetWorkTransport {
    client: SyncClient,
    repository: String,
}

impl WorkTransport for NetWorkTransport {
    fn request(&mut self, data: Vec<u8>) -> Result<Vec<u8>> {
        let response = self.client.request(
            protocol::PATH_WORK,
            request_with_repository(data, &self.repository)?,
        )?;
        let bytes = protocol::response_bin(&response.data)?;
        decode_status(bytes)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct WorkOptions {
    config_dir: Option<PathBuf>,
    rns_config_dir: Option<PathBuf>,
    remote: String,
    command: WorkCommand,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum WorkCommand {
    List {
        scope: String,
    },
    View {
        scope: String,
        id: u64,
    },
    Create {
        title: String,
        content_path: PathBuf,
    },
    Edit {
        scope: String,
        id: u64,
        title: Option<String>,
        content_path: Option<PathBuf>,
    },
    Delete {
        scope: String,
        id: u64,
        yes: bool,
    },
    Comment {
        scope: String,
        id: u64,
        content_path: PathBuf,
    },
    Perms {
        id: u64,
        content_path: Option<PathBuf>,
    },
    Complete {
        id: u64,
    },
    Activate {
        id: u64,
    },
}

impl WorkOptions {
    fn parse<I>(args: I) -> Result<Self>
    where
        I: IntoIterator<Item = String>,
    {
        let mut config_dir = None;
        let mut rns_config_dir = None;
        let mut scope = "active".to_string();
        let mut id = None;
        let mut title = None;
        let mut content_path = None;
        let mut yes = false;
        let mut positional = Vec::new();
        let mut args = args.into_iter();
        while let Some(arg) = args.next() {
            match arg.as_str() {
                "-c" | "--config" => {
                    config_dir = Some(PathBuf::from(
                        args.next()
                            .ok_or_else(|| Error::msg("missing config path"))?,
                    ));
                }
                "--rnsconfig" => {
                    rns_config_dir = Some(PathBuf::from(
                        args.next()
                            .ok_or_else(|| Error::msg("missing RNS config path"))?,
                    ));
                }
                "--scope" => {
                    scope = args.next().ok_or_else(|| Error::msg("missing scope"))?;
                }
                "-d" | "--id" => {
                    id = Some(parse_id(
                        &args
                            .next()
                            .ok_or_else(|| Error::msg("missing document ID"))?,
                    )?);
                }
                "-t" | "--title" => {
                    title = Some(args.next().ok_or_else(|| Error::msg("missing title"))?);
                }
                "--content" => {
                    content_path = Some(PathBuf::from(
                        args.next()
                            .ok_or_else(|| Error::msg("missing content path"))?,
                    ));
                }
                "-y" | "--yes" => yes = true,
                "-h" | "--help" => return Err(Error::msg(usage())),
                other => positional.push(other.to_string()),
            }
        }
        if positional.len() < 2 {
            return Err(Error::msg(usage()));
        }
        let remote = positional[0].clone();
        let command = match positional[1].as_str() {
            "list" => WorkCommand::List { scope },
            "view" => WorkCommand::View {
                scope,
                id: id
                    .or_else(|| positional.get(2).and_then(|value| parse_id(value).ok()))
                    .ok_or_else(|| Error::msg("work view requires --id"))?,
            },
            "create" => WorkCommand::Create {
                title: title.ok_or_else(|| Error::msg("work create requires --title"))?,
                content_path: content_path
                    .ok_or_else(|| Error::msg("work create requires --content"))?,
            },
            "edit" => WorkCommand::Edit {
                scope,
                id: id.ok_or_else(|| Error::msg("work edit requires --id"))?,
                title,
                content_path,
            },
            "delete" => WorkCommand::Delete {
                scope,
                id: id.ok_or_else(|| Error::msg("work delete requires --id"))?,
                yes,
            },
            "comment" | "update" => WorkCommand::Comment {
                scope,
                id: id.ok_or_else(|| Error::msg("work comment requires --id"))?,
                content_path: content_path
                    .ok_or_else(|| Error::msg("work comment requires --content"))?,
            },
            "perms" => WorkCommand::Perms {
                id: id.ok_or_else(|| Error::msg("work perms requires --id"))?,
                content_path,
            },
            "complete" => WorkCommand::Complete {
                id: id.ok_or_else(|| Error::msg("work complete requires --id"))?,
            },
            "activate" => WorkCommand::Activate {
                id: id.ok_or_else(|| Error::msg("work activate requires --id"))?,
            },
            other => return Err(Error::msg(format!("unknown work operation {other}"))),
        };
        Ok(Self {
            config_dir,
            rns_config_dir,
            remote,
            command,
        })
    }
}

fn run_work_command(
    transport: &mut impl WorkTransport,
    command: &WorkCommand,
    mut output: impl Write,
) -> Result<()> {
    match command {
        WorkCommand::List { scope } => {
            let body =
                transport.request(request("list", &[("scope", Value::Str(scope.clone()))]))?;
            let value = msgpack::unpack_exact(&body)
                .map_err(|e| Error::msg(format!("invalid work list: {e}")))?;
            print_work_list(&value, &mut output)
        }
        WorkCommand::View { scope, id } => {
            let body = transport.request(request(
                "view",
                &[
                    ("scope", Value::Str(scope.clone())),
                    ("doc_id", Value::UInt(*id)),
                ],
            ))?;
            let value = msgpack::unpack_exact(&body)
                .map_err(|e| Error::msg(format!("invalid work document: {e}")))?;
            print_work_document(&value, &mut output)
        }
        WorkCommand::Create {
            title,
            content_path,
        } => {
            let content = fs::read_to_string(content_path)?;
            let body = transport.request(request(
                "create",
                &[
                    ("title", Value::Str(title.clone())),
                    ("content", Value::Str(content)),
                    ("format", Value::Str(format_for_path(content_path))),
                ],
            ))?;
            let value = msgpack::unpack_exact(&body)
                .map_err(|e| Error::msg(format!("invalid create response: {e}")))?;
            writeln!(
                output,
                "Created work document {} #{}",
                value
                    .map_get("scope")
                    .and_then(Value::as_str)
                    .unwrap_or("active"),
                value.map_get("id").and_then(Value::as_integer).unwrap_or(0)
            )?;
            Ok(())
        }
        WorkCommand::Edit {
            scope,
            id,
            title,
            content_path,
        } => {
            let mut fields = vec![
                ("scope", Value::Str(scope.clone())),
                ("doc_id", Value::UInt(*id)),
            ];
            if let Some(title) = title {
                fields.push(("title", Value::Str(title.clone())));
            }
            if let Some(path) = content_path {
                fields.push(("content", Value::Str(fs::read_to_string(path)?)));
            }
            transport.request(request("edit", &fields))?;
            writeln!(output, "Updated work document {scope} #{id}")?;
            Ok(())
        }
        WorkCommand::Delete { scope, id, yes } => {
            if !yes {
                return Err(Error::msg("work delete requires --yes"));
            }
            transport.request(request(
                "delete",
                &[
                    ("scope", Value::Str(scope.clone())),
                    ("doc_id", Value::UInt(*id)),
                ],
            ))?;
            writeln!(output, "Deleted work document {scope} #{id}")?;
            Ok(())
        }
        WorkCommand::Comment {
            scope,
            id,
            content_path,
        } => {
            let body = transport.request(request(
                "comment",
                &[
                    ("scope", Value::Str(scope.clone())),
                    ("doc_id", Value::UInt(*id)),
                    ("content", Value::Str(fs::read_to_string(content_path)?)),
                    ("format", Value::Str(format_for_path(content_path))),
                ],
            ))?;
            let value = msgpack::unpack_exact(&body)
                .map_err(|e| Error::msg(format!("invalid comment response: {e}")))?;
            writeln!(
                output,
                "Added update #{} to {scope} document #{id}",
                value.map_get("id").and_then(Value::as_integer).unwrap_or(0)
            )?;
            Ok(())
        }
        WorkCommand::Perms { id, content_path } => {
            if let Some(path) = content_path {
                transport.request(request(
                    "perms",
                    &[
                        ("doc_id", Value::UInt(*id)),
                        ("step", Value::Str("set".into())),
                        ("content", Value::Str(fs::read_to_string(path)?)),
                    ],
                ))?;
                writeln!(output, "Updated permissions for work document #{id}")?;
            } else {
                let body = transport.request(request(
                    "perms",
                    &[
                        ("doc_id", Value::UInt(*id)),
                        ("step", Value::Str("get".into())),
                    ],
                ))?;
                let value = msgpack::unpack_exact(&body)
                    .map_err(|e| Error::msg(format!("invalid permissions response: {e}")))?;
                write!(
                    output,
                    "{}",
                    value
                        .map_get("content")
                        .and_then(Value::as_str)
                        .unwrap_or("")
                )?;
            }
            Ok(())
        }
        WorkCommand::Complete { id } => {
            transport.request(request("complete", &[("doc_id", Value::UInt(*id))]))?;
            writeln!(output, "Completed work document #{id}")?;
            Ok(())
        }
        WorkCommand::Activate { id } => {
            transport.request(request("activate", &[("doc_id", Value::UInt(*id))]))?;
            writeln!(output, "Activated work document #{id}")?;
            Ok(())
        }
    }
}

fn request(operation: &str, fields: &[(&str, Value)]) -> Vec<u8> {
    let mut map = vec![
        (
            Value::UInt(protocol::IDX_REPOSITORY),
            Value::Str("__repository__".into()),
        ),
        (
            Value::Str("operation".into()),
            Value::Str(operation.to_string()),
        ),
    ];
    map.extend(
        fields
            .iter()
            .map(|(key, value)| (Value::Str((*key).into()), value.clone())),
    );
    msgpack::pack(&Value::Map(map))
}

fn request_with_repository(data: Vec<u8>, repository: &str) -> Result<Vec<u8>> {
    let mut value =
        msgpack::unpack_exact(&data).map_err(|e| Error::msg(format!("invalid request: {e}")))?;
    if let Value::Map(entries) = &mut value {
        for (key, val) in entries {
            if matches!(key, Value::UInt(v) if *v == protocol::IDX_REPOSITORY) {
                *val = Value::Str(repository.to_string());
                return Ok(msgpack::pack(&value));
            }
        }
    }
    Err(Error::msg("work request missing repository field"))
}

fn print_work_list(value: &Value, mut output: impl Write) -> Result<()> {
    let active = value
        .map_get("active")
        .and_then(Value::as_array)
        .unwrap_or(&[]);
    let completed = value
        .map_get("completed")
        .and_then(Value::as_array)
        .unwrap_or(&[]);
    if active.is_empty() && completed.is_empty() {
        writeln!(output, "No work documents")?;
        return Ok(());
    }
    print_work_section("Active documents", active, &mut output)?;
    print_work_section("Completed documents", completed, &mut output)?;
    Ok(())
}

fn print_work_section(title: &str, docs: &[Value], mut output: impl Write) -> Result<()> {
    if docs.is_empty() {
        return Ok(());
    }
    writeln!(output, "{title}")?;
    for doc in docs {
        writeln!(
            output,
            "#{} {} ({} update(s))",
            doc.map_get("id").and_then(Value::as_integer).unwrap_or(0),
            doc.map_get("title")
                .and_then(Value::as_str)
                .unwrap_or("Untitled"),
            doc.map_get("comments")
                .and_then(Value::as_integer)
                .unwrap_or(0)
        )?;
    }
    Ok(())
}

fn print_work_document(value: &Value, mut output: impl Write) -> Result<()> {
    let title = value
        .map_get("meta")
        .and_then(|meta| meta.map_get("title"))
        .and_then(Value::as_str)
        .unwrap_or("Untitled");
    writeln!(
        output,
        "{} (#{} {})",
        title,
        value.map_get("id").and_then(Value::as_integer).unwrap_or(0),
        value
            .map_get("scope")
            .and_then(Value::as_str)
            .unwrap_or("active")
    )?;
    writeln!(
        output,
        "{}",
        value
            .map_get("content")
            .and_then(Value::as_str)
            .unwrap_or("")
    )?;
    let comments = value
        .map_get("comments")
        .and_then(Value::as_array)
        .unwrap_or(&[]);
    for comment in comments {
        writeln!(
            output,
            "\nUpdate #{}\n{}",
            comment
                .map_get("id")
                .and_then(Value::as_integer)
                .unwrap_or(0),
            comment
                .map_get("content")
                .and_then(Value::as_str)
                .unwrap_or("")
        )?;
    }
    Ok(())
}

fn parse_id(value: &str) -> Result<u64> {
    value.parse().map_err(|_| Error::msg("invalid document ID"))
}

fn format_for_path(path: &std::path::Path) -> String {
    if path.extension().and_then(|ext| ext.to_str()) == Some("mu") {
        "micron".into()
    } else {
        "markdown".into()
    }
}

fn usage() -> &'static str {
    "usage: rngit work [--config DIR] [--rnsconfig DIR] [--scope active|completed|all] [--id N] [--title TITLE] [--content PATH] [-y|--yes] <rns://destination/repo> <list|view|create|edit|delete|comment|perms|complete|activate>"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Default)]
    struct FakeTransport {
        requests: Vec<Value>,
        responses: Vec<Vec<u8>>,
    }

    impl WorkTransport for FakeTransport {
        fn request(&mut self, data: Vec<u8>) -> Result<Vec<u8>> {
            self.requests.push(msgpack::unpack_exact(&data).unwrap());
            Ok(self.responses.remove(0))
        }
    }

    #[test]
    fn parses_work_commands() {
        assert_eq!(
            WorkOptions::parse(args(&[
                "rns://00112233445566778899aabbccddeeff/group/repo",
                "list",
                "--scope",
                "all",
            ]))
            .unwrap()
            .command,
            WorkCommand::List {
                scope: "all".into()
            }
        );
        assert_eq!(
            WorkOptions::parse(args(&[
                "rns://00112233445566778899aabbccddeeff/group/repo",
                "view",
                "--id",
                "7",
            ]))
            .unwrap()
            .command,
            WorkCommand::View {
                scope: "active".into(),
                id: 7,
            }
        );
        assert!(WorkOptions::parse(args(&[
            "rns://00112233445566778899aabbccddeeff/group/repo",
            "create",
            "--title",
            "Task",
        ]))
        .is_err());
        assert_eq!(
            WorkOptions::parse(args(&[
                "rns://00112233445566778899aabbccddeeff/group/repo",
                "perms",
                "--id",
                "7",
            ]))
            .unwrap()
            .command,
            WorkCommand::Perms {
                id: 7,
                content_path: None,
            }
        );
    }

    #[test]
    fn create_sends_work_create_request() {
        let tmp = tempfile::tempdir().unwrap();
        let content = tmp.path().join("WORK.md");
        fs::write(&content, "# Body\n").unwrap();
        let mut transport = FakeTransport {
            requests: Vec::new(),
            responses: vec![msgpack::pack(&Value::Map(vec![
                (Value::Str("id".into()), Value::UInt(3)),
                (Value::Str("scope".into()), Value::Str("active".into())),
            ]))],
        };
        let mut output = Vec::new();
        run_work_command(
            &mut transport,
            &WorkCommand::Create {
                title: "Task".into(),
                content_path: content,
            },
            &mut output,
        )
        .unwrap();
        assert!(String::from_utf8(output).unwrap().contains("active #3"));
        assert_eq!(
            transport.requests[0]
                .map_get("operation")
                .and_then(Value::as_str),
            Some("create")
        );
        assert_eq!(
            transport.requests[0]
                .map_get("content")
                .and_then(Value::as_str),
            Some("# Body\n")
        );
    }

    #[test]
    fn list_and_view_format_responses() {
        let mut transport = FakeTransport {
            requests: Vec::new(),
            responses: vec![
                msgpack::pack(&Value::Map(vec![(
                    Value::Str("active".into()),
                    Value::Array(vec![Value::Map(vec![
                        (Value::Str("id".into()), Value::UInt(1)),
                        (Value::Str("title".into()), Value::Str("Task".into())),
                        (Value::Str("comments".into()), Value::UInt(2)),
                    ])]),
                )])),
                msgpack::pack(&Value::Map(vec![
                    (Value::Str("id".into()), Value::UInt(1)),
                    (Value::Str("scope".into()), Value::Str("active".into())),
                    (Value::Str("content".into()), Value::Str("Body".into())),
                    (
                        Value::Str("meta".into()),
                        Value::Map(vec![(
                            Value::Str("title".into()),
                            Value::Str("Task".into()),
                        )]),
                    ),
                    (
                        Value::Str("comments".into()),
                        Value::Array(vec![Value::Map(vec![
                            (Value::Str("id".into()), Value::UInt(1)),
                            (Value::Str("content".into()), Value::Str("Update".into())),
                        ])]),
                    ),
                ])),
            ],
        };
        let mut output = Vec::new();
        run_work_command(
            &mut transport,
            &WorkCommand::List {
                scope: "active".into(),
            },
            &mut output,
        )
        .unwrap();
        run_work_command(
            &mut transport,
            &WorkCommand::View {
                scope: "active".into(),
                id: 1,
            },
            &mut output,
        )
        .unwrap();
        let output = String::from_utf8(output).unwrap();
        assert!(output.contains("#1 Task (2 update(s))"));
        assert!(output.contains("Task (#1 active)"));
        assert!(output.contains("Update #1"));
    }

    #[test]
    fn delete_requires_yes_and_lifecycle_commands_send_requests() {
        let tmp = tempfile::tempdir().unwrap();
        let comment_path = tmp.path().join("COMMENT.md");
        fs::write(&comment_path, "Update").unwrap();
        let mut transport = FakeTransport {
            requests: Vec::new(),
            responses: vec![
                msgpack::pack(&Value::Map(vec![(Value::Str("id".into()), Value::UInt(1))])),
                Vec::new(),
                Vec::new(),
                Vec::new(),
            ],
        };
        assert!(run_work_command(
            &mut transport,
            &WorkCommand::Delete {
                scope: "active".into(),
                id: 1,
                yes: false,
            },
            Vec::new(),
        )
        .is_err());
        run_work_command(
            &mut transport,
            &WorkCommand::Comment {
                scope: "active".into(),
                id: 1,
                content_path: comment_path,
            },
            Vec::new(),
        )
        .unwrap();
        run_work_command(&mut transport, &WorkCommand::Complete { id: 1 }, Vec::new()).unwrap();
        run_work_command(&mut transport, &WorkCommand::Activate { id: 1 }, Vec::new()).unwrap();
        run_work_command(
            &mut transport,
            &WorkCommand::Delete {
                scope: "active".into(),
                id: 1,
                yes: true,
            },
            Vec::new(),
        )
        .unwrap();
        let ops: Vec<_> = transport
            .requests
            .iter()
            .filter_map(|request| request.map_get("operation").and_then(Value::as_str))
            .collect();
        assert_eq!(ops, vec!["comment", "complete", "activate", "delete"]);
    }

    #[test]
    fn edit_sends_title_and_content_when_provided() {
        let tmp = tempfile::tempdir().unwrap();
        let content = tmp.path().join("EDIT.md");
        fs::write(&content, "Edited body\n").unwrap();
        let mut transport = FakeTransport {
            requests: Vec::new(),
            responses: vec![Vec::new()],
        };

        run_work_command(
            &mut transport,
            &WorkCommand::Edit {
                scope: "active".into(),
                id: 9,
                title: Some("Edited title".into()),
                content_path: Some(content),
            },
            Vec::new(),
        )
        .unwrap();

        let request = &transport.requests[0];
        assert_eq!(
            request.map_get("operation").and_then(Value::as_str),
            Some("edit")
        );
        assert_eq!(
            request.map_get("title").and_then(Value::as_str),
            Some("Edited title")
        );
        assert_eq!(
            request.map_get("content").and_then(Value::as_str),
            Some("Edited body\n")
        );
    }

    #[test]
    fn perms_get_and_set_send_work_permission_requests() {
        let tmp = tempfile::tempdir().unwrap();
        let permissions = tmp.path().join("allowed.txt");
        fs::write(&permissions, "interact = all\n").unwrap();
        let mut transport = FakeTransport {
            requests: Vec::new(),
            responses: vec![
                msgpack::pack(&Value::Map(vec![(
                    Value::Str("content".into()),
                    Value::Str("admin = all\n".into()),
                )])),
                Vec::new(),
            ],
        };
        let mut output = Vec::new();
        run_work_command(
            &mut transport,
            &WorkCommand::Perms {
                id: 3,
                content_path: None,
            },
            &mut output,
        )
        .unwrap();
        run_work_command(
            &mut transport,
            &WorkCommand::Perms {
                id: 3,
                content_path: Some(permissions),
            },
            &mut output,
        )
        .unwrap();
        assert!(String::from_utf8(output).unwrap().contains("admin = all"));
        assert_eq!(
            transport.requests[0]
                .map_get("operation")
                .and_then(Value::as_str),
            Some("perms")
        );
        assert_eq!(
            transport.requests[0]
                .map_get("step")
                .and_then(Value::as_str),
            Some("get")
        );
        assert_eq!(
            transport.requests[1]
                .map_get("step")
                .and_then(Value::as_str),
            Some("set")
        );
        assert_eq!(
            transport.requests[1]
                .map_get("content")
                .and_then(Value::as_str),
            Some("interact = all\n")
        );
    }

    fn args(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| value.to_string()).collect()
    }
}
