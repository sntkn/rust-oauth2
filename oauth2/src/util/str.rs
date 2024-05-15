use rand::{distributions::Alphanumeric, Rng};

pub fn generate_random_string(len: usize) -> String {
    let random_bytes: Vec<u8> = rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(len)
        .collect();
    String::from_utf8(random_bytes).unwrap()
}
