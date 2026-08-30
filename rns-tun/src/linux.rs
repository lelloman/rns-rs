use std::ffi::CString;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::platform::{AppliedTunnelConfig, PacketDevice, TunnelConfig, TunnelConfigurator};

const TUNSETIFF: libc::c_ulong = 0x4004_54ca;
const IFF_TUN: libc::c_short = 0x0001;
const IFF_NO_PI: libc::c_short = 0x1000;

#[repr(C)]
struct IfReq {
    name: [libc::c_char; libc::IFNAMSIZ],
    flags: libc::c_short,
    padding: [u8; 22],
}

pub struct TunDevice {
    file: File,
    name: String,
}

impl TunDevice {
    pub fn open(requested_name: &str) -> io::Result<Self> {
        validate_interface_name(requested_name)?;
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/net/tun")?;
        Self::configure(file, requested_name)
    }

    /// Take ownership of an already-open TUN descriptor. The descriptor must
    /// already be configured as an L3 `IFF_TUN | IFF_NO_PI` device.
    pub fn from_owned_fd(fd: OwnedFd, name: &str) -> io::Result<Self> {
        validate_interface_name(name)?;
        Ok(Self {
            file: File::from(fd),
            name: name.to_owned(),
        })
    }

    /// Duplicate a borrowed descriptor, leaving ownership of the original with
    /// the caller.
    pub fn duplicate_fd(fd: RawFd, name: &str) -> io::Result<Self> {
        validate_interface_name(name)?;
        let duplicate = unsafe { libc::dup(fd) };
        if duplicate < 0 {
            return Err(io::Error::last_os_error());
        }
        let owned = unsafe { OwnedFd::from_raw_fd(duplicate) };
        Self::from_owned_fd(owned, name)
    }

    fn configure(file: File, requested_name: &str) -> io::Result<Self> {
        let mut request = IfReq {
            name: [0; libc::IFNAMSIZ],
            flags: IFF_TUN | IFF_NO_PI,
            padding: [0; 22],
        };
        for (slot, byte) in request.name.iter_mut().zip(requested_name.bytes()) {
            *slot = byte as libc::c_char;
        }
        if unsafe { libc::ioctl(file.as_raw_fd(), TUNSETIFF, &mut request) } < 0 {
            return Err(io::Error::last_os_error());
        }
        let bytes: Vec<u8> = request
            .name
            .iter()
            .take_while(|value| **value != 0)
            .map(|value| *value as u8)
            .collect();
        let name = String::from_utf8(bytes)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid TUN name"))?;
        Ok(Self { file, name })
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn try_clone(&self) -> io::Result<Self> {
        Ok(Self {
            file: self.file.try_clone()?,
            name: self.name.clone(),
        })
    }

    pub fn set_nonblocking(&self, enabled: bool) -> io::Result<()> {
        let flags = unsafe { libc::fcntl(self.file.as_raw_fd(), libc::F_GETFL) };
        if flags < 0 {
            return Err(io::Error::last_os_error());
        }
        let updated = if enabled {
            flags | libc::O_NONBLOCK
        } else {
            flags & !libc::O_NONBLOCK
        };
        if unsafe { libc::fcntl(self.file.as_raw_fd(), libc::F_SETFL, updated) } < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
}

impl PacketDevice for TunDevice {
    fn read_packet(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        self.file.read(buffer)
    }
    fn write_packet(&mut self, packet: &[u8]) -> io::Result<()> {
        let mut offset = 0;
        while offset < packet.len() {
            match self.file.write(&packet[offset..]) {
                Ok(0) => {
                    return Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "TUN write returned zero",
                    ))
                }
                Ok(written) => offset += written,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(1));
                }
                Err(error) => return Err(error),
            }
        }
        Ok(())
    }
    fn close(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn validate_interface_name(name: &str) -> io::Result<()> {
    if name.is_empty()
        || name.len() >= libc::IFNAMSIZ
        || !name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-'))
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid interface name",
        ));
    }
    Ok(())
}

trait CommandRunner: Send {
    fn output(&mut self, program: &str, args: &[String]) -> io::Result<Output>;
}

struct SystemRunner;
impl CommandRunner for SystemRunner {
    fn output(&mut self, program: &str, args: &[String]) -> io::Result<Output> {
        Command::new(program).args(args).output()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct OwnedCommand {
    program: String,
    remove_args: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct OwnershipJournal {
    schema_version: u8,
    process_id: u32,
    interface_name: String,
    cleanup: Vec<OwnedCommand>,
}

/// Linux configuration backend. Commands are executed directly without a
/// shell, and every successful mutation records its exact inverse before the
/// session is reported ready.
pub struct LinuxConfigurator {
    underlay_mark: u32,
    routing_table: u32,
    physical_table: u32,
    underlay_priority: u32,
    tunnel_priority: u32,
    journal_path: PathBuf,
    runner: Box<dyn CommandRunner>,
    inherited_fd: Option<OwnedFd>,
}

impl LinuxConfigurator {
    pub fn new(
        underlay_mark: u32,
        routing_table: u32,
        physical_table: u32,
        underlay_priority: u32,
        tunnel_priority: u32,
        journal_path: PathBuf,
    ) -> io::Result<Self> {
        if underlay_mark == 0 || underlay_priority >= tunnel_priority {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid policy routing values",
            ));
        }
        Ok(Self {
            underlay_mark,
            routing_table,
            physical_table,
            underlay_priority,
            tunnel_priority,
            journal_path,
            runner: Box::new(SystemRunner),
            inherited_fd: None,
        })
    }

    pub fn with_tun_fd(mut self, fd: OwnedFd) -> Self {
        self.inherited_fd = Some(fd);
        self
    }

    pub fn cleanup_stale(&mut self) -> io::Result<()> {
        if !self.journal_path.exists() {
            return Ok(());
        }
        let journal: OwnershipJournal = serde_json::from_slice(&fs::read(&self.journal_path)?)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        if journal.process_id != std::process::id() && process_is_alive(journal.process_id) {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                format!(
                    "refusing cleanup while owning process {} is alive",
                    journal.process_id
                ),
            ));
        }
        self.cleanup_commands(&journal.cleanup)?;
        fs::remove_file(&self.journal_path)
    }

    fn run(&mut self, program: &str, args: Vec<String>) -> io::Result<String> {
        let output = self.runner.output(program, &args)?;
        if !output.status.success() {
            return Err(io::Error::other(format!(
                "{} {} failed: {}",
                program,
                args.join(" "),
                String::from_utf8_lossy(&output.stderr).trim()
            )));
        }
        Ok(String::from_utf8_lossy(&output.stdout).into_owned())
    }

    fn mutate(
        &mut self,
        journal: &mut OwnershipJournal,
        program: &str,
        add_args: Vec<String>,
        remove_args: Vec<String>,
    ) -> io::Result<()> {
        self.run(program, add_args)?;
        journal.cleanup.push(OwnedCommand {
            program: program.into(),
            remove_args,
        });
        write_journal(&self.journal_path, journal)
    }

    fn cleanup_commands(&mut self, commands: &[OwnedCommand]) -> io::Result<()> {
        let mut first_error = None;
        for command in commands.iter().rev() {
            match self.runner.output(&command.program, &command.remove_args) {
                Ok(output) if output.status.success() => {}
                Ok(output)
                    if cleanup_target_is_absent(
                        &command.program,
                        &String::from_utf8_lossy(&output.stderr),
                    ) => {}
                Ok(output) => {
                    first_error.get_or_insert_with(|| {
                        io::Error::other(format!(
                            "{} {} failed: {}",
                            command.program,
                            command.remove_args.join(" "),
                            String::from_utf8_lossy(&output.stderr).trim()
                        ))
                    });
                }
                Err(error) => {
                    first_error.get_or_insert(error);
                }
            }
        }
        first_error.map_or(Ok(()), Err)
    }
}

impl TunnelConfigurator for LinuxConfigurator {
    type Device = TunDevice;

    fn apply(&mut self, config: &TunnelConfig) -> io::Result<(Self::Device, AppliedTunnelConfig)> {
        validate_interface_name(&config.interface_name)?;
        if self.journal_path.exists() {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                format!(
                    "stale ownership journal {}; run cleanup",
                    self.journal_path.display()
                ),
            ));
        }
        let device = match self.inherited_fd.take() {
            Some(fd) => TunDevice::from_owned_fd(fd, &config.interface_name)?,
            None => TunDevice::open(&config.interface_name)?,
        };
        let name = device.name().to_owned();
        let mut journal = OwnershipJournal {
            schema_version: 1,
            process_id: std::process::id(),
            interface_name: name.clone(),
            cleanup: Vec::new(),
        };
        write_journal(&self.journal_path, &journal)?;

        let result = (|| {
            self.mutate(
                &mut journal,
                "ip",
                strings(&[
                    "address",
                    "add",
                    &format!("{}/{}", config.address, config.prefix_len),
                    "dev",
                    &name,
                ]),
                strings(&[
                    "address",
                    "del",
                    &format!("{}/{}", config.address, config.prefix_len),
                    "dev",
                    &name,
                ]),
            )?;
            self.run(
                "ip",
                strings(&[
                    "link",
                    "set",
                    "dev",
                    &name,
                    "mtu",
                    &config.mtu.to_string(),
                    "up",
                ]),
            )?;
            for route in &config.routes {
                self.mutate(
                    &mut journal,
                    "ip",
                    strings(&[
                        "route",
                        "add",
                        &route.to_string(),
                        "dev",
                        &name,
                        "table",
                        &self.routing_table.to_string(),
                    ]),
                    strings(&[
                        "route",
                        "del",
                        &route.to_string(),
                        "dev",
                        &name,
                        "table",
                        &self.routing_table.to_string(),
                    ]),
                )?;
                if !config.full_tunnel && route.prefix_len() != 0 {
                    self.mutate(
                        &mut journal,
                        "ip",
                        strings(&[
                            "rule",
                            "add",
                            "to",
                            &route.to_string(),
                            "lookup",
                            &self.routing_table.to_string(),
                            "priority",
                            &self.tunnel_priority.to_string(),
                        ]),
                        strings(&[
                            "rule",
                            "del",
                            "to",
                            &route.to_string(),
                            "lookup",
                            &self.routing_table.to_string(),
                            "priority",
                            &self.tunnel_priority.to_string(),
                        ]),
                    )?;
                }
            }
            if config.full_tunnel {
                self.mutate(
                    &mut journal,
                    "ip",
                    strings(&[
                        "route",
                        "add",
                        "blackhole",
                        "default",
                        "metric",
                        "32767",
                        "table",
                        &self.routing_table.to_string(),
                    ]),
                    strings(&[
                        "route",
                        "del",
                        "blackhole",
                        "default",
                        "metric",
                        "32767",
                        "table",
                        &self.routing_table.to_string(),
                    ]),
                )?;
                self.mutate(
                    &mut journal,
                    "ip",
                    strings(&[
                        "route",
                        "add",
                        "default",
                        "dev",
                        &name,
                        "metric",
                        "10",
                        "table",
                        &self.routing_table.to_string(),
                    ]),
                    strings(&[
                        "route",
                        "del",
                        "default",
                        "dev",
                        &name,
                        "metric",
                        "10",
                        "table",
                        &self.routing_table.to_string(),
                    ]),
                )?;
                self.mutate(
                    &mut journal,
                    "ip",
                    strings(&[
                        "rule",
                        "add",
                        "fwmark",
                        &self.underlay_mark.to_string(),
                        "lookup",
                        &self.physical_table.to_string(),
                        "priority",
                        &self.underlay_priority.to_string(),
                    ]),
                    strings(&[
                        "rule",
                        "del",
                        "fwmark",
                        &self.underlay_mark.to_string(),
                        "lookup",
                        &self.physical_table.to_string(),
                        "priority",
                        &self.underlay_priority.to_string(),
                    ]),
                )?;
                self.mutate(
                    &mut journal,
                    "ip",
                    strings(&[
                        "rule",
                        "add",
                        "not",
                        "fwmark",
                        &self.underlay_mark.to_string(),
                        "lookup",
                        &self.routing_table.to_string(),
                        "priority",
                        &self.tunnel_priority.to_string(),
                    ]),
                    strings(&[
                        "rule",
                        "del",
                        "not",
                        "fwmark",
                        &self.underlay_mark.to_string(),
                        "lookup",
                        &self.routing_table.to_string(),
                        "priority",
                        &self.tunnel_priority.to_string(),
                    ]),
                )?;
                self.mutate(
                    &mut journal,
                    "ip",
                    strings(&[
                        "-6",
                        "rule",
                        "add",
                        "not",
                        "fwmark",
                        &self.underlay_mark.to_string(),
                        "prohibit",
                        "priority",
                        &self.tunnel_priority.to_string(),
                    ]),
                    strings(&[
                        "-6",
                        "rule",
                        "del",
                        "not",
                        "fwmark",
                        &self.underlay_mark.to_string(),
                        "prohibit",
                        "priority",
                        &self.tunnel_priority.to_string(),
                    ]),
                )?;
                let mut dns_args = strings(&["dns", &name]);
                dns_args.extend(config.dns_servers.iter().map(ToString::to_string));
                self.run("resolvectl", dns_args)?;
                journal.cleanup.push(OwnedCommand {
                    program: "resolvectl".into(),
                    remove_args: strings(&["revert", &name]),
                });
                write_journal(&self.journal_path, &journal)?;
                self.run("resolvectl", strings(&["domain", &name, "~."]))?;
                self.run("resolvectl", strings(&["flush-caches"]))?;
            }
            Ok(())
        })();
        if let Err(error) = result {
            let _ = self.cleanup_commands(&journal.cleanup);
            let _ = fs::remove_file(&self.journal_path);
            return Err(error);
        }
        let applied = AppliedTunnelConfig {
            interface_name: name,
            ifindex: None,
            dns_servers: config.dns_servers.clone(),
            full_tunnel_verified: config.full_tunnel,
        };
        if let Err(error) = self.verify(&applied) {
            let _ = self.cleanup_commands(&journal.cleanup);
            let _ = fs::remove_file(&self.journal_path);
            return Err(error);
        }
        Ok((device, applied))
    }

    fn verify(&self, applied: &AppliedTunnelConfig) -> io::Result<()> {
        if !applied.full_tunnel_verified {
            return Ok(());
        }
        // Use fresh commands here so verification cannot mutate ownership state.
        let rules = Command::new("ip").args(["rule", "show"]).output()?;
        let routes = Command::new("ip")
            .args(["route", "show", "table", &self.routing_table.to_string()])
            .output()?;
        let ipv6_rules = Command::new("ip").args(["-6", "rule", "show"]).output()?;
        let dns = Command::new("resolvectl")
            .args(["status", &applied.interface_name])
            .output()?;
        let combined = format!(
            "{}\n{}\n{}\n{}",
            String::from_utf8_lossy(&rules.stdout),
            String::from_utf8_lossy(&routes.stdout),
            String::from_utf8_lossy(&ipv6_rules.stdout),
            String::from_utf8_lossy(&dns.stdout)
        );
        if !rules.status.success()
            || !routes.status.success()
            || !ipv6_rules.status.success()
            || !dns.status.success()
            || !combined.contains(&format!("lookup {}", self.routing_table))
            || !combined.contains("blackhole default")
            || !combined.contains("prohibit")
            || !combined.contains("~.")
            || applied
                .dns_servers
                .iter()
                .any(|ip| !combined.contains(&ip.to_string()))
        {
            return Err(io::Error::other(
                "full-tunnel route/DNS verification failed",
            ));
        }
        Ok(())
    }

    fn teardown(&mut self, _applied: &AppliedTunnelConfig) -> io::Result<()> {
        self.cleanup_stale()
    }
}

fn strings(values: &[&str]) -> Vec<String> {
    values.iter().map(|value| (*value).to_owned()).collect()
}

fn process_is_alive(process_id: u32) -> bool {
    let result = unsafe { libc::kill(process_id as libc::pid_t, 0) };
    result == 0 || io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
}

fn cleanup_target_is_absent(program: &str, stderr: &str) -> bool {
    program == "ip"
        && [
            "Cannot find device",
            "No such process",
            "Cannot assign requested address",
        ]
        .iter()
        .any(|message| stderr.contains(message))
}

fn write_journal(path: &Path, journal: &OwnershipJournal) -> io::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let temporary = path.with_extension(format!("tmp-{}", std::process::id()));
    let data = serde_json::to_vec_pretty(journal).map_err(io::Error::other)?;
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&temporary)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(fs::Permissions::from_mode(0o600))?;
    }
    file.write_all(&data)?;
    file.sync_all()?;
    fs::rename(&temporary, path)?;
    if let Some(parent) = path.parent() {
        File::open(parent)?.sync_all()?;
    }
    Ok(())
}

#[allow(dead_code)]
fn _cstring(value: &str) -> io::Result<CString> {
    CString::new(value).map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "NUL byte"))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rejects_unsafe_names() {
        assert!(validate_interface_name("rntun0").is_ok());
        assert!(validate_interface_name("rntun;bad").is_err());
        assert!(validate_interface_name("").is_err());
    }
    #[test]
    fn rejects_policy_priority_inversion() {
        assert!(LinuxConfigurator::new(1, 2, 254, 110, 100, "x".into()).is_err());
    }
    #[test]
    fn stale_ip_cleanup_accepts_only_absent_targets() {
        assert!(cleanup_target_is_absent(
            "ip",
            "Cannot find device \"rntun0\""
        ));
        assert!(cleanup_target_is_absent(
            "ip",
            "RTNETLINK answers: No such process"
        ));
        assert!(!cleanup_target_is_absent("ip", "Operation not permitted"));
        assert!(!cleanup_target_is_absent("resolvectl", "No such process"));
    }
}
