use clap::{Parser, Subcommand};

#[derive(Parser)]
struct Args {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    DistDir,
}

fn main() {
    let args = Args::parse();
    match args.command {
        Command::DistDir => dist(),
    }
}

fn dist() {
    let dist = scratch::path("dist");
    let dist = dist.to_str().unwrap();
    println!("{dist}");
}
