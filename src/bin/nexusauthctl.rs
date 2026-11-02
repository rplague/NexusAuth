#[tokio::main]
async fn main() {
    std::process::exit(nexusauth::ctl::run().await);
}
