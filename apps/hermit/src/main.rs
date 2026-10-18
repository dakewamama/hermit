mod chain;
mod cli;
mod cmd;
mod ctx;
mod home;
mod store;
mod witness;
mod zcash;
mod zewif_export;

use clap::Parser;

fn main() {
    let cli = cli::Cli::parse();
    // The only exit point: everything (temporary directories holding
    // decrypted wallet data included) has been dropped by the time we leave.
    if let Err(e) = cmd::run(cli) {
        match e.downcast_ref::<ctx::Refusal>() {
            Some(r) => {
                eprintln!("{}", r.msg);
                std::process::exit(r.code);
            }
            None => {
                eprintln!("error: {e:#}");
                std::process::exit(1);
            }
        }
    }
}
