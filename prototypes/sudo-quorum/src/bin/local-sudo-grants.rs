#[tokio::main]
async fn main() {
    if ipars_host_authorization_prototype::local::serve()
        .await
        .is_err()
    {
        eprintln!("local sudo privilege grant service unavailable");
        std::process::exit(1);
    }
}
