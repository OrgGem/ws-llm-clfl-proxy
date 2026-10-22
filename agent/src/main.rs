use std::ffi::OsString;
use std::fs::File;
use std::io::{self, Read};
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

use ws_llm_agent::{GatewayConfig, GatewayProvider};
use yoagent::context::ExecutionLimits;
use yoagent::{Agent, AgentEvent, RetryConfig, StopReason, StreamDelta};

const DEFAULT_ENV_FILE: &str = ".env";
const MAX_TASK_BYTES: usize = 32 * 1024;
const MAX_OUTPUT_BYTES: usize = 16 * 1024 * 1024;
const MAX_RUN_SECONDS: u64 = 300;
const CANCELLATION_GRACE_SECONDS: u64 = 5;

#[derive(Debug, PartialEq, Eq)]
struct Options {
    env_file: PathBuf,
    memory_config: Option<PathBuf>,
    task_file: Option<PathBuf>,
    help: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RunFailure {
    InputFailed,
    ConfigurationFailed,
    #[cfg(feature = "memory")]
    MemoryFailed,
    OutputLimit,
    TimedOut,
    Cancelled,
    Incomplete,
    ProviderFailed,
    StreamClosed,
    OutputFailed,
}

fn main() -> ExitCode {
    let options = match parse_args(std::env::args_os()) {
        Ok(options) => options,
        Err(()) => {
            eprintln!("invalid command options; use --help for usage");
            return ExitCode::from(2);
        }
    };

    if options.help {
        print_help();
        return ExitCode::SUCCESS;
    }

    #[cfg(not(feature = "memory"))]
    if options.memory_config.is_some() {
        eprintln!("memory support is not compiled in; rebuild with --features memory");
        return ExitCode::from(2);
    }

    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(_) => {
            eprintln!("could not start the async runtime");
            return ExitCode::FAILURE;
        }
    };

    let result = runtime.block_on(run(options));
    // Tokio's stdout bridge may have a blocking-pool write waiting on a full
    // pipe. Never let runtime teardown wait forever after the request was
    // already cancelled or timed out.
    runtime.shutdown_timeout(Duration::from_secs(CANCELLATION_GRACE_SECONDS));

    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(RunFailure::Cancelled) => {
            eprintln!("agent run cancelled");
            ExitCode::from(130)
        }
        Err(failure) => {
            eprintln!("{}", failure_message(failure));
            ExitCode::FAILURE
        }
    }
}

fn parse_args<I>(args: I) -> Result<Options, ()>
where
    I: IntoIterator<Item = OsString>,
{
    let mut args = args.into_iter();
    let _program = args.next();
    let mut env_file = None;
    let mut memory_config = None;
    let mut task_file = None;
    let mut help = false;

    while let Some(arg) = args.next() {
        match arg.to_str() {
            Some("--help" | "-h") => help = true,
            Some("--config-env") => {
                if env_file.is_some() {
                    return Err(());
                }
                env_file = Some(PathBuf::from(args.next().ok_or(())?));
            }
            Some("--memory-config") => {
                if memory_config.is_some() {
                    return Err(());
                }
                memory_config = Some(PathBuf::from(args.next().ok_or(())?));
            }
            Some("--task-file") => {
                if task_file.is_some() {
                    return Err(());
                }
                let path = PathBuf::from(args.next().ok_or(())?);
                task_file = if path.as_os_str() == "-" {
                    None
                } else {
                    Some(path)
                };
            }
            _ => return Err(()),
        }
    }

    Ok(Options {
        env_file: env_file.unwrap_or_else(|| PathBuf::from(DEFAULT_ENV_FILE)),
        memory_config,
        task_file,
        help,
    })
}

async fn run(options: Options) -> Result<(), RunFailure> {
    let task = read_task(options.task_file.as_deref()).map_err(|_| RunFailure::InputFailed)?;
    let gateway_config = GatewayConfig::from_env_file(&options.env_file)
        .map_err(|_| RunFailure::ConfigurationFailed)?;
    let model_config = gateway_config.model_config();
    let provider =
        GatewayProvider::new(gateway_config).map_err(|_| RunFailure::ConfigurationFailed)?;

    let mut agent = Agent::from_provider(provider, model_config)
        .with_system_prompt(
            "You are a helpful assistant. Answer the user's task directly. ".to_string(),
        )
        .with_retry_config(RetryConfig::none())
        .with_execution_limits(
            ExecutionLimits::default()
                .with_max_turns(12)
                .with_max_total_tokens(1_000_000)
                .with_max_duration(Duration::from_secs(MAX_RUN_SECONDS)),
        );

    #[cfg(feature = "memory")]
    let memory_tasks = if let Some(memory_path) = options.memory_config.as_deref() {
        let (memory_agent, tasks) =
            install_memory(agent, memory_path).map_err(|_| RunFailure::MemoryFailed)?;
        agent = memory_agent;
        Some(tasks)
    } else {
        None
    };

    let mut events = agent.prompt(task).await;
    let mut stdout = tokio::io::stdout();
    let result = tokio::select! {
        result = consume_events(&mut events, &mut stdout) => result,
        _ = tokio::time::sleep(Duration::from_secs(MAX_RUN_SECONDS)) => {
            agent.abort();
            Err(RunFailure::TimedOut)
        }
        _ = tokio::signal::ctrl_c() => {
            agent.abort();
            Err(RunFailure::Cancelled)
        }
    };

    if result.is_err() {
        agent.abort();
        let _ = tokio::time::timeout(
            Duration::from_secs(CANCELLATION_GRACE_SECONDS),
            agent.finish(),
        )
        .await;
        #[cfg(feature = "memory")]
        if let Some(tasks) = memory_tasks.as_ref() {
            if drain_memory_tasks(tasks).await.is_err() {
                return Err(RunFailure::MemoryFailed);
            }
        }
        return result;
    }

    if tokio::time::timeout(
        Duration::from_secs(CANCELLATION_GRACE_SECONDS),
        agent.finish(),
    )
    .await
    .is_err()
    {
        agent.abort();
        let _ = tokio::time::timeout(
            Duration::from_secs(CANCELLATION_GRACE_SECONDS),
            agent.finish(),
        )
        .await;
        #[cfg(feature = "memory")]
        if let Some(tasks) = memory_tasks.as_ref() {
            if drain_memory_tasks(tasks).await.is_err() {
                return Err(RunFailure::MemoryFailed);
            }
        }
        return Err(RunFailure::StreamClosed);
    }
    #[cfg(feature = "memory")]
    if let Some(tasks) = memory_tasks.as_ref() {
        drain_memory_tasks(tasks).await?;
    }
    result
}

async fn consume_events<W>(
    events: &mut tokio::sync::mpsc::UnboundedReceiver<AgentEvent>,
    stdout: &mut W,
) -> Result<(), RunFailure>
where
    W: tokio::io::AsyncWrite + Unpin,
{
    use tokio::io::AsyncWriteExt;

    let mut output_bytes = 0usize;
    while let Some(event) = events.recv().await {
        match event {
            AgentEvent::MessageUpdate {
                delta: StreamDelta::Text { delta },
                ..
            } => {
                output_bytes = output_bytes
                    .checked_add(delta.len())
                    .ok_or(RunFailure::OutputLimit)?;
                if output_bytes > MAX_OUTPUT_BYTES {
                    return Err(RunFailure::OutputLimit);
                }
                stdout
                    .write_all(delta.as_bytes())
                    .await
                    .map_err(|_| RunFailure::OutputFailed)?;
                stdout.flush().await.map_err(|_| RunFailure::OutputFailed)?;
            }
            AgentEvent::AgentEnd { messages, .. } => {
                let stop_reason = messages.iter().rev().find_map(|message| {
                    let llm_message = message.as_llm()?;
                    match llm_message {
                        yoagent::Message::Assistant { stop_reason, .. } => {
                            Some(stop_reason.clone())
                        }
                        _ => None,
                    }
                });

                return match stop_reason {
                    Some(reason) => terminal_status(&reason),
                    None => Err(RunFailure::ProviderFailed),
                };
            }
            _ => {}
        }
    }
    Err(RunFailure::StreamClosed)
}

fn read_task(path: Option<&std::path::Path>) -> io::Result<String> {
    let mut reader: Box<dyn Read> = match path {
        Some(path) => Box::new(File::open(path)?),
        None => Box::new(io::stdin()),
    };
    let mut bytes = Vec::with_capacity(MAX_TASK_BYTES.min(4096));
    reader
        .by_ref()
        .take((MAX_TASK_BYTES + 1) as u64)
        .read_to_end(&mut bytes)?;
    if bytes.len() > MAX_TASK_BYTES || bytes.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid task size",
        ));
    }
    let task = String::from_utf8(bytes)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "task must be UTF-8"))?;
    if task.trim().is_empty() {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "task is empty"));
    }
    Ok(task)
}

#[cfg(feature = "memory")]
fn install_memory(
    mut agent: Agent,
    path: &std::path::Path,
) -> Result<(Agent, yoagent::memory_integration::MemoryHookTasks), ()> {
    use std::sync::Arc;
    use yoagent::memory_integration::{
        install_memory_hooks_tracked, MemoryHookTasks, MemoryManageTool, MemorySaveTool,
        MemoryService, UtekeMemory,
    };
    use zeroize::Zeroize;

    let mut memory = read_memory_config(path)?;
    let backend = memory.backend.trim().to_ascii_lowercase();
    if !matches!(backend.as_str(), "ollama" | "openai")
        || memory.db_path.trim().is_empty()
        || memory.db_path.trim() == "memory"
        || memory.db_path.trim().ends_with(".sqlite")
    {
        memory.api_key.zeroize();
        return Err(());
    }
    if backend == "openai"
        && memory.api_key.trim().is_empty()
        && std::env::var("UTEKE_EMBEDDING_API_KEY")
            .ok()
            .is_none_or(|key| key.trim().is_empty())
    {
        // Do not let the memory backend silently borrow OPENAI_API_KEY: in a
        // local client environment that value can be an unrelated SDK token.
        memory.api_key.zeroize();
        return Err(());
    }

    if prepare_memory_store(&memory).is_err() {
        memory.api_key.zeroize();
        return Err(());
    }
    let memory_path = memory.resolved_db_path();
    let memory_result = UtekeMemory::from_config(&memory);
    memory.api_key.zeroize();
    let memory = memory_result.map_err(|_| ())?;
    restrict_memory_file(&memory_path)?;
    let service = MemoryService::new(Arc::new(memory), 64, Duration::from_secs(5));
    let tasks = MemoryHookTasks::default();
    agent = install_memory_hooks_tracked(agent, service.clone(), 4, tasks.clone());
    agent = agent.with_tools(vec![
        Box::new(MemorySaveTool {
            service: service.clone(),
        }),
        Box::new(MemoryManageTool { service }),
    ]);
    Ok((agent, tasks))
}

#[cfg(feature = "memory")]
async fn drain_memory_tasks(
    tasks: &yoagent::memory_integration::MemoryHookTasks,
) -> Result<(), RunFailure> {
    tokio::time::timeout(
        Duration::from_secs(CANCELLATION_GRACE_SECONDS),
        tasks.drain(),
    )
    .await
    .map_err(|_| RunFailure::MemoryFailed)?
    .map_err(|_| RunFailure::MemoryFailed)
}

#[cfg(feature = "memory")]
fn read_memory_config(path: &std::path::Path) -> Result<yoagent::config::MemoryConfig, ()> {
    use serde::Deserialize;
    use std::fs::OpenOptions;
    use zeroize::Zeroize;

    const MAX_MEMORY_CONFIG_BYTES: u64 = 64 * 1024;

    #[derive(Deserialize, Default)]
    #[serde(default)]
    struct MemoryOnlyConfig {
        memory: yoagent::config::MemoryConfig,
    }

    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW);
    }
    let mut file = options.open(path).map_err(|_| ())?;
    let metadata = file.metadata().map_err(|_| ())?;
    if !metadata.is_file() || metadata.len() > MAX_MEMORY_CONFIG_BYTES {
        return Err(());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if metadata.mode() & 0o777 != 0o600 || metadata.uid() != unsafe { libc::geteuid() } {
            return Err(());
        }
    }

    let mut contents = Vec::with_capacity(metadata.len() as usize);
    if file
        .by_ref()
        .take(MAX_MEMORY_CONFIG_BYTES + 1)
        .read_to_end(&mut contents)
        .is_err()
    {
        contents.zeroize();
        return Err(());
    }
    if contents.len() as u64 > MAX_MEMORY_CONFIG_BYTES {
        contents.zeroize();
        return Err(());
    }

    let is_toml = path.extension().and_then(|extension| extension.to_str()) == Some("toml");
    let parsed = if is_toml {
        match std::str::from_utf8(&contents) {
            Ok(text) => toml::from_str::<MemoryOnlyConfig>(text).map_err(|_| ()),
            Err(_) => Err(()),
        }
    } else {
        serde_json::from_slice::<MemoryOnlyConfig>(&contents).map_err(|_| ())
    };
    contents.zeroize();
    let config = parsed.map_err(|_| ())?;
    Ok(config.memory)
}

#[cfg(feature = "memory")]
fn prepare_memory_store(config: &yoagent::config::MemoryConfig) -> Result<(), ()> {
    let path = config.resolved_db_path();
    let parent = path.parent().ok_or(())?;
    std::fs::create_dir_all(parent).map_err(|_| ())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700)).map_err(|_| ())?;
    }
    // SQLite can open its sidecars during initialization too. Tighten all
    // existing files before Uteke/SQLite sees them, and reject links that
    // could make stored facts reachable outside this private directory.
    tighten_existing_memory_file(&path)?;
    for suffix in ["-wal", "-shm", "-journal"] {
        let mut sidecar = path.as_os_str().to_os_string();
        sidecar.push(suffix);
        tighten_existing_memory_file(std::path::Path::new(&sidecar))?;
    }
    Ok(())
}

#[cfg(feature = "memory")]
fn tighten_existing_memory_file(path: &std::path::Path) -> Result<(), ()> {
    let metadata = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(_) => return Err(()),
    };
    if !metadata.file_type().is_file() {
        return Err(());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        if metadata.uid() != unsafe { libc::geteuid() } || metadata.nlink() != 1 {
            return Err(());
        }
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).map_err(|_| ())?;
    }
    Ok(())
}

#[cfg(feature = "memory")]
fn restrict_memory_file(path: &std::path::Path) -> Result<(), ()> {
    let metadata = std::fs::symlink_metadata(path).map_err(|_| ())?;
    if !metadata.file_type().is_file() {
        return Err(());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        if metadata.uid() != unsafe { libc::geteuid() } || metadata.nlink() != 1 {
            return Err(());
        }
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).map_err(|_| ())?;
    }
    Ok(())
}

fn terminal_status(stop_reason: &StopReason) -> Result<(), RunFailure> {
    match stop_reason {
        StopReason::Stop | StopReason::Refusal => Ok(()),
        StopReason::Length | StopReason::Error | StopReason::Aborted => Err(RunFailure::Incomplete),
        _ => Err(RunFailure::Incomplete),
    }
}

fn failure_message(failure: RunFailure) -> &'static str {
    match failure {
        RunFailure::InputFailed => "task input is empty, invalid UTF-8, unreadable, or over 32 KiB",
        RunFailure::ConfigurationFailed => "Gateway configuration or encrypted envelope is invalid",
        #[cfg(feature = "memory")]
        RunFailure::MemoryFailed => {
            "memory initialization or a pending memory operation failed or timed out"
        }
        RunFailure::OutputLimit => "agent output exceeded the configured limit",
        RunFailure::TimedOut => "agent run exceeded the time limit",
        RunFailure::Cancelled => "agent run cancelled",
        RunFailure::Incomplete => "agent run ended without a complete response",
        RunFailure::ProviderFailed => {
            "Gateway request failed; check Identity and Gateway configuration"
        }
        RunFailure::StreamClosed => "Gateway stream closed before a terminal response",
        RunFailure::OutputFailed => "could not write the agent response",
    }
}

fn print_help() {
    println!(
        "ws-llm-agent [--config-env FILE] [--memory-config FILE] [--task-file FILE]\n\
         Reads task text from stdin when --task-file is omitted. Task content is never accepted as an argument.\n\
         --config-env FILE    protected WS_PROXY_* environment file (default: .env)\n\
         --memory-config FILE opt in to YoAgent memory using its original config format (requires feature memory)\n\
         --task-file FILE     read a bounded UTF-8 task from FILE; use - for stdin\n\
         -h, --help           show this help"
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(values: &[&str]) -> Vec<OsString> {
        values.iter().map(OsString::from).collect()
    }

    #[test]
    fn defaults_to_protected_dotenv_and_stdin() {
        let options = parse_args(args(&["ws-llm-agent"])).unwrap();
        assert_eq!(options.env_file, PathBuf::from(".env"));
        assert_eq!(options.task_file, None);
        assert_eq!(options.memory_config, None);
    }

    #[test]
    fn accepts_config_memory_and_task_files_without_task_argument() {
        let options = parse_args(args(&[
            "ws-llm-agent",
            "--config-env",
            "agent/.env.example",
            "--memory-config",
            "agent/memory.json",
            "--task-file",
            "private/task.txt",
        ]))
        .unwrap();
        assert_eq!(options.env_file, PathBuf::from("agent/.env.example"));
        assert_eq!(
            options.memory_config,
            Some(PathBuf::from("agent/memory.json"))
        );
        assert_eq!(options.task_file, Some(PathBuf::from("private/task.txt")));
    }

    #[test]
    fn refuses_prompt_text_in_arguments_and_duplicate_files() {
        assert!(parse_args(args(&["ws-llm-agent", "--task", "secret prompt"])).is_err());
        assert!(parse_args(args(&[
            "ws-llm-agent",
            "--task-file",
            "task.txt",
            "--task-file",
            "other.txt",
        ]))
        .is_err());
    }

    #[test]
    fn stdin_marker_is_explicit() {
        let options = parse_args(args(&["ws-llm-agent", "--task-file", "-"])).unwrap();
        assert_eq!(options.task_file, None);
    }

    #[test]
    fn task_reader_rejects_empty_and_oversized_files() {
        let dir = tempfile::tempdir().unwrap();
        let empty = dir.path().join("empty.txt");
        std::fs::write(&empty, b" \n").unwrap();
        assert!(read_task(Some(&empty)).is_err());

        let large = dir.path().join("large.txt");
        std::fs::write(&large, vec![b'a'; MAX_TASK_BYTES + 1]).unwrap();
        assert!(read_task(Some(&large)).is_err());
    }

    #[test]
    fn incomplete_agent_terminals_are_nonzero_failures() {
        for reason in [StopReason::Length, StopReason::Error, StopReason::Aborted] {
            assert_eq!(terminal_status(&reason), Err(RunFailure::Incomplete));
        }
        assert_eq!(terminal_status(&StopReason::Stop), Ok(()));
    }

    #[tokio::test]
    async fn backpressured_output_writer_does_not_block_the_run_deadline() {
        use std::pin::Pin;
        use std::task::{Context, Poll};

        struct PendingWriter;
        impl tokio::io::AsyncWrite for PendingWriter {
            fn poll_write(
                self: Pin<&mut Self>,
                _context: &mut Context<'_>,
                _buffer: &[u8],
            ) -> Poll<io::Result<usize>> {
                Poll::Pending
            }

            fn poll_flush(
                self: Pin<&mut Self>,
                _context: &mut Context<'_>,
            ) -> Poll<io::Result<()>> {
                Poll::Pending
            }

            fn poll_shutdown(
                self: Pin<&mut Self>,
                _context: &mut Context<'_>,
            ) -> Poll<io::Result<()>> {
                Poll::Ready(Ok(()))
            }
        }

        let (sender, mut events) = tokio::sync::mpsc::unbounded_channel();
        sender
            .send(AgentEvent::MessageUpdate {
                message: yoagent::AgentMessage::from(yoagent::Message::user("test")),
                delta: StreamDelta::Text {
                    delta: "response".to_owned(),
                },
            })
            .unwrap();
        drop(sender);
        let mut writer = PendingWriter;
        assert!(tokio::time::timeout(
            Duration::from_millis(20),
            consume_events(&mut events, &mut writer),
        )
        .await
        .is_err());
    }

    #[cfg(feature = "memory")]
    #[test]
    fn memory_config_requires_owner_only_regular_file_and_accepts_json() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("memory.json");
        std::fs::write(
            &path,
            br#"{"memory":{"backend":"ollama","model":"nomic-embed-text","base_url":"http://127.0.0.1:11434","api_key":"","dims":768,"endpoint_path":"","db_path":".agent-state/project-a"}}"#,
        )
        .unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }

        let config = read_memory_config(&path).unwrap();
        assert_eq!(config.backend, "ollama");
        assert_eq!(config.db_path, ".agent-state/project-a");

        #[cfg(unix)]
        {
            use std::os::unix::fs::{symlink, PermissionsExt};
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o640)).unwrap();
            assert!(read_memory_config(&path).is_err());
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
            let link = dir.path().join("linked-memory.json");
            symlink(&path, &link).unwrap();
            assert!(read_memory_config(&link).is_err());
        }
    }

    #[cfg(feature = "memory")]
    #[test]
    fn memory_config_accepts_toml_under_protected_file_mode() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("memory.toml");
        std::fs::write(
            &path,
            "[memory]\nbackend = \"ollama\"\nmodel = \"nomic-embed-text\"\nbase_url = \"http://127.0.0.1:11434\"\napi_key = \"\"\ndims = 768\nendpoint_path = \"\"\ndb_path = \".agent-state/project-a\"\n",
        )
        .unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        let config = read_memory_config(&path).unwrap();
        assert_eq!(config.backend, "ollama");
    }

    #[cfg(all(feature = "memory", unix))]
    #[test]
    fn memory_database_is_tightened_before_use_and_symlinks_are_rejected() {
        use std::os::unix::fs::{symlink, PermissionsExt};

        let dir = tempfile::tempdir().unwrap();
        let mut config = yoagent::config::MemoryConfig {
            backend: "ollama".to_owned(),
            model: "nomic-embed-text".to_owned(),
            db_path: dir
                .path()
                .join("private-store")
                .to_string_lossy()
                .into_owned(),
            ..yoagent::config::MemoryConfig::default()
        };
        let db = config.resolved_db_path();
        std::fs::create_dir_all(db.parent().unwrap()).unwrap();
        std::fs::write(&db, b"test database placeholder").unwrap();
        std::fs::set_permissions(&db, std::fs::Permissions::from_mode(0o644)).unwrap();

        prepare_memory_store(&config).unwrap();
        assert_eq!(
            std::fs::metadata(db.parent().unwrap())
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
        assert_eq!(
            std::fs::metadata(&db).unwrap().permissions().mode() & 0o777,
            0o600
        );

        let target = dir.path().join("target.sqlite");
        std::fs::write(&target, b"target").unwrap();
        let link_root = dir.path().join("link-store");
        config.db_path = link_root.to_string_lossy().into_owned();
        let link = config.resolved_db_path();
        std::fs::create_dir_all(link.parent().unwrap()).unwrap();
        symlink(&target, &link).unwrap();
        assert!(prepare_memory_store(&config).is_err());

        let wal_root = dir.path().join("wal-store");
        config.db_path = wal_root.to_string_lossy().into_owned();
        let wal_db = config.resolved_db_path();
        std::fs::create_dir_all(wal_db.parent().unwrap()).unwrap();
        let mut wal_path = wal_db.as_os_str().to_os_string();
        wal_path.push("-wal");
        symlink(&target, std::path::Path::new(&wal_path)).unwrap();
        assert!(prepare_memory_store(&config).is_err());
    }
}
