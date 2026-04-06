use std::process::Command;

fn main() {
    println!("RetroOS init");

    // Compile COMMAND.COM via BCC
    println!("Building COMMAND.COM...");
    let _ = Command::new("BORLANDC/BIN/BCC.EXE")
        .args(&[
            "BCC.EXE",
            "-IBORLANDC\\INCLUDE",
            "-LBORLANDC\\LIB",
            "-mt",
            "-eCOMMAND.COM",
            "COMMAND.C",
        ])
        .status();

    // Run DN
    let _ = Command::new("DN/DN.COM").arg("DN.COM").status();
}
