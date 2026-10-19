mod chain;
mod cli;
mod cmd;
mod ctx;
mod home;
mod net;
mod pairing;
mod store;
mod witness;
mod zcash;
mod zewif_export;
mod zewif_import;

use clap::Parser;

fn main() {
    // Behave like any Unix tool when the reader goes away (`hermit log |
    // head`): end quietly instead of panicking on a broken pipe.
    #[cfg(unix)]
    unsafe {
        libc::signal(libc::SIGPIPE, libc::SIG_DFL);
    }
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
