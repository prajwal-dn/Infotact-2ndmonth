use fuser::MountOption;
use quantumvault::filesystem::QuantumVaultFs;
use std::env;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mountpoint = env::args()
        .nth(1)
        .expect("Usage: quantumvault-mount <mountpoint>");

    let options = [
        MountOption::RW,
        MountOption::FSName("quantumvault".to_string()),
    ];

    println!("Mounting QuantumVault at {mountpoint}");

    fuser::mount2(QuantumVaultFs::new(), mountpoint, &options)?;

    println!("QuantumVault unmounted.");
    Ok(())
}
