fn main() {
    if let Err(err) = sandsifter::injector_rs::run() {
        eprintln!("{err}");
        std::process::exit(1);
    }
}
