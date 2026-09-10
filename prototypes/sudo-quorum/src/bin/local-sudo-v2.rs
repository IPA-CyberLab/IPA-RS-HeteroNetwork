#[tokio::main]
async fn main() {
    if ipars_host_authorization_prototype::local_v2::serve()
        .await
        .is_err()
    {
        eprintln!("local sudo-v2 service unavailable");
        std::process::exit(1);
    }
}
