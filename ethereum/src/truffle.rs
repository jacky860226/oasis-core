use ekiden_common::error::Error;
use ekiden_common::futures::{future, stream, BoxStream, Future};
use rustc_hex::FromHex;
use std;
use std::io::Read;
use std::process::{Child, Command, Stdio};
use std::{env, thread, time};
use web3;

/// The hard coded truffle development Ethereum address, taken from
/// http://truffleframework.com/docs/getting_started/console (entry 0).
pub const DEVELOPMENT_ADDRESS: &'static [u8] =
    b"\x62\x73\x06\x09\x0a\xba\xb3\xa6\xe1\x40\x0e\x93\x45\xbc\x60\xc7\x8a\x8b\xef\x57";

/// Start at truffle develop instance and return a handle for testing against.
pub fn start_truffle(cwd: &str) -> Child {
    if env::var("EXTERNAL_BLOCKCHAIN").is_ok() {
        Command::new("ls")
            .stdout(Stdio::null())
            .spawn()
            .expect("Odd")
    } else {
        let mut child = Command::new("truffle")
            .arg("develop")
            .current_dir(cwd)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .expect("Could not start truffle develop backend");
        // Block until output
        {
            let mut waiter = [0; 64];
            let stdout = child.stdout.as_mut();
            let _ = stdout.unwrap().read(&mut waiter);
        }
        child
    }
}

/// Deploy a named contract in the current truffle context.
/// return the etherum address it is deployed to.
pub fn deploy_truffle(name: &str, cwd: &str) -> Vec<u8> {
    let migrate = Command::new("truffle")
        .arg("migrate")
        .arg("--reset")
        .current_dir(cwd)
        .output()
        .unwrap();
    let output = String::from_utf8_lossy(&migrate.stdout);
    let contract_address = output
        .lines()
        .filter_map(|x| {
            if x.starts_with(&format!("  {}", name)) {
                Some(x.trim().rsplit(" ").next())
            } else {
                None
            }
        })
        .next()
        .expect(&format!("Truffle deployment failed: {:?}", output))
        .unwrap();
    let address = contract_address.split_at(2).1.from_hex().unwrap();
    address
}

/// Run truffle test in the current working directory.
pub fn test_truffle(cwd: &str) {
    let status = Command::new("truffle")
        .arg("test")
        .arg("--network=test") // The `=` is mandatory, truffle bug?
        .current_dir(cwd)
        .status()
        .expect("truffle failed");
    assert!(status.success());
}

/// Make a stream of transactions between two truffle default accts to keep the chain going.
pub fn mine<T: 'static + web3::Transport + Sync + Send>(tport: T) -> BoxStream<u64>
where
    <T as web3::Transport>::Out: std::marker::Send,
{
    Box::new(stream::unfold(0, move |state| {
        thread::sleep(time::Duration::from_millis(500));
        Some(
            tport
                .execute("evm_mine", vec![])
                .then(move |_r| future::ok::<(u64, u64), Error>((0, state + 1))),
        )
    }))
}
