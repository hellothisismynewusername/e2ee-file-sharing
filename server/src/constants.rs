// A token corresponds to 1 allowed ws_file_upload()
/// Time in ms for the per-email upload limiter to replenish by 1 token
pub const UPLOAD_RATE_LIMIT_EMAIL_REPLENISH_TIME: u64 = 2000;
/// Time in ms for the per-IP upload limiter limit bucket to replenish by 1 token
pub const UPLOAD_RATE_LIMIT_IP_REPLENISH_TIME: u64 = 1000;
/// Maximum number of upload requests allowed in a burst per email
pub const UPLOAD_RATE_LIMIT_EMAIL_BURST_SIZE: u32 = 5;
/// Maximum number of upload requests allowed in a burst per IP
pub const UPLOAD_RATE_LIMIT_IP_BURST_SIZE: u32 = 10;

// A token corresponds to 1 allowed general API call (list_files, get_file, etc.)
/// Time in ms for the per-email general limiter to replenish by 1 token
pub const GENERAL_RATE_LIMIT_EMAIL_REPLENISH_TIME: u64 = 200;
/// Time in ms for the per-IP general limiter limit bucket to replenish by 1 token
pub const GENERAL_RATE_LIMIT_IP_REPLENISH_TIME: u64 = 100;
/// Maximum number of general API requests allowed in a burst per email
pub const GENERAL_RATE_LIMIT_EMAIL_BURST_SIZE: u32 = 30;
/// Maximum number of general API requests allowed in a burst per IP
pub const GENERAL_RATE_LIMIT_IP_BURST_SIZE: u32 = 60;

pub fn development_mode_from_env() -> bool {
    match std::env::var("EFS_SERVER_DEVELOPMENT_MODE") {
        Ok(variable) => match variable.as_ref() {
            "1" => {
                println!("DEVELOPMENT_MODE is enabled");
                true
            }
            _ => false,
        },
        Err(_) => {
            println!(
                "Environment variable 'EFS_SERVER_DEVELOPMENT_MODE' is not set, defaulting to false"
            );
            false
        }
    }
}
