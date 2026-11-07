use remxo::config::AppPaths;
use remxo::error::AppError;
use std::ffi::OsString;
use std::path::PathBuf;
use std::process::ExitCode;

fn main() -> ExitCode {
    let arguments = std::env::args_os().collect::<Vec<_>>();
    if std::env::var_os("REMXO_ASKPASS_CONFIG").is_some() {
        let prompt = arguments.into_iter().skip(1).collect();
        return run_runtime(remxo::cli::askpass_entry(prompt));
    }
    if let Some(config) = detached_broker_config(&arguments) {
        let paths = match AppPaths::new(config) {
            Ok(paths) => paths,
            Err(error) => return fatal(error),
        };
        #[cfg(unix)]
        let paths = match remxo::broker::daemonize_broker(&paths) {
            Ok(paths) => paths,
            Err(error) => return fatal(error),
        };
        return run_runtime(async {
            match remxo::broker::serve(paths).await {
                Ok(()) => ExitCode::SUCCESS,
                Err(error) => fatal(error),
            }
        });
    }
    run_runtime(remxo::cli::main_entry())
}

fn detached_broker_config(arguments: &[OsString]) -> Option<Option<PathBuf>> {
    match arguments {
        [_, action] if action == "__broker-daemon" => Some(None),
        [_, flag, config, action] if flag == "--config" && action == "__broker-daemon" => {
            Some(Some(PathBuf::from(config)))
        }
        _ => None,
    }
}

fn run_runtime(future: impl std::future::Future<Output = ExitCode>) -> ExitCode {
    match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime.block_on(future),
        Err(error) => fatal(AppError::io("start async runtime", error)),
    }
}

fn fatal(error: AppError) -> ExitCode {
    eprintln!("remxo [{:?}]: {}", error.code, error.message);
    ExitCode::from(2)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn daemon_args_are_only_detected_in_the_exact_internal_shape() {
        let expected = detached_broker_config(&[
            "remxo".into(),
            "--config".into(),
            "nested/config.toml".into(),
            "__broker-daemon".into(),
        ]);
        assert_eq!(expected, Some(Some(PathBuf::from("nested/config.toml"))));
        assert_eq!(
            detached_broker_config(&["remxo".into(), "prod".into(), "__broker-daemon".into()]),
            None
        );
        assert_eq!(
            detached_broker_config(&["remxo".into(), "__broker-daemon".into()]),
            Some(None)
        );
        assert_eq!(
            detached_broker_config(&[
                "remxo".into(),
                "__broker-daemon".into(),
                "--config".into(),
                "unexpected".into(),
            ]),
            None
        );
    }
}
