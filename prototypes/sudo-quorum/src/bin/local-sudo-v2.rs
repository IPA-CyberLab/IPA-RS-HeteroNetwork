fn check_only(args: &[std::ffi::OsString]) -> Result<bool, ()> {
    match args {
        [] => Ok(false),
        [flag] if flag == "--check-config" => Ok(true),
        _ => Err(()),
    }
}

#[tokio::main]
async fn main() {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    let check = match check_only(&args) {
        Ok(check) => check,
        Err(()) => {
            eprintln!("usage: local-sudo-v2 [--check-config]");
            std::process::exit(1);
        }
    };
    if check {
        if ipars_host_authorization_prototype::local_v2::check_config().is_err() {
            eprintln!("local sudo-v2 configuration rejected");
            std::process::exit(1);
        }
        println!("local sudo-v2 configuration valid; no runtime state opened");
        return;
    }
    if ipars_host_authorization_prototype::local_v2::serve()
        .await
        .is_err()
    {
        eprintln!("local sudo-v2 service unavailable");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn check_config_only_accepts_exact_flag_without_path_overrides() {
        assert_eq!(super::check_only(&[]), Ok(false));
        assert_eq!(super::check_only(&["--check-config".into()]), Ok(true));
        for args in [
            vec!["--config", "/tmp/config"],
            vec!["--check-config", "/tmp/config"],
            vec!["--check-config", "--check-config"],
            vec!["--unknown"],
        ] {
            assert!(
                super::check_only(&args.into_iter().map(Into::into).collect::<Vec<_>>()).is_err()
            );
        }
    }
}
