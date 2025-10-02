use safe_txe_circuit::{Input, circuit};

/// Arguments:
/// 1. <hex> RLP-encoded public input
/// 2. <hex> RLP-encoded private input
fn main() {
    let input = Input::from_args();
    circuit(&input);
}
