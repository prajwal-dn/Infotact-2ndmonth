use fuser::MountOption;
use std::env;

use quantumvault::filesystem::QuantumVaultFs;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mountpoint = env::args()
        .nth(1)
        .expect("Usage: quantumvault-mount <mountpoint>");

    let options = [
        MountOption::RO,
        MountOption::FSName("quantumvault".to_string()),
    ];

    println!("Mounting QuantumVault at {mountpoint}");

    fuser::mount2(QuantumVaultFs, mountpoint, &options)?;

    println!("QuantumVault unmounted.");

    Ok(())
}
