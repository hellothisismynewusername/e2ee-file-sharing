use std::{
    ffi::{CStr, CString, c_char},
    fs::File,
    panic::UnwindSafe,
    path::{Path, PathBuf},
};

use corelib::client::PkKeyPair;

use crate::{ApiCallError, get_user_info};

/// Do *not* use this until initialized by one of the other exposed API functions; use this to create a handle to pass into exposed API functions.  
///
/// Use `free_PkKeyPair()` to free `PkKeyPair`s.  
///
/// # Returns  
///
/// An opaque handle for `PkKeyPair`
#[unsafe(no_mangle)]
pub extern "C" fn new_PkKeyPair() -> *mut PkKeyPair {
    return Box::into_raw(Box::new(PkKeyPair::new()));
}

/// Use this to free `PkKeyPair`s.
#[unsafe(no_mangle)]
pub extern "C" fn free_PkKeyPair(ptr: *mut PkKeyPair) {
    if !ptr.is_null() {
        unsafe {
            let _tmp = Box::from_raw(ptr);
        }
    }
}

/// Use this function to free strings allocated in rust code (as opposed to standard `free()`).
#[unsafe(no_mangle)]
pub extern "C" fn free_String(ptr: *mut c_char) {
    if !ptr.is_null() {
        unsafe {
            let _tmp = CString::from_raw(ptr);
        }
    }
}

pub const ERR_PANIC: i32 = -67;

// we want panic = "unwind" (instead of "abort"), although the build in debug & release should already be like that by default.
fn ffi_catch_unwind_wrapper(func: impl FnOnce() -> i32 + UnwindSafe) -> i32 {
    match std::panic::catch_unwind(func) {
        Ok(func_return) => func_return,
        Err(payload) => {
            std::mem::forget(payload); // dropping a custom panic payload can panic itself supposedly
            ERR_PANIC
        }
    }
}

/// Decrypts the user's private key and fetches their user info from the server  
///
/// # Arguments  
///
/// * `server_url` - The URL of the server.
/// * `email` - The email of the user.
/// * `password` - The password of the user.
/// * `disk_key_path` - The path to the disk key directory.
/// * `out_error` - Optional, pass in null or pass in a pre-allocated buffer of at least `512` bytes.
/// * `out_error_len` - Max capacity of `out_error` should you choose to use it. Must be at least `512`.  
///
/// Out params:
/// * `out_key_pair` - Use `new_PkKeyPair()` to get a `PkKeyPair` handle to pass in.
/// * `out_password_hash` - The buffer to receive the null-terminated password hash.
/// * `out_password_hash_capacity` - The size of the password hash buffer.
/// * `out_user_id` - Ensure this isn't null and also is aligned.  
///
/// # Returns  
///
/// Error codes:
/// * `-1` - Parameter error (null ptrs, `out_key_pair` or `out_user_id` isn't aligned).
/// * `-2` - Non-null `out_error` was passed in, but `out_error_len` capacity is not at least `512` bytes.
/// * `-3` - Internal casting errors
/// * `-4` - Password hash buffer is too small.
/// * `-5` - Email/password fail, writes to `out_error` if not null.
/// * `-6` - Other server fail, writes to `out_error` if not null.
/// * `-7` - Inexplicable other server fail, does not write to `out_error`.
/// * `-67` (`ERR_PANIC`) - Caught panic.  
///
/// Good path out params:  
///
/// A `PkKeyPair` opaque handle through `out_key_pair`, and the password hash and user id as the other mutable outputs.
#[unsafe(no_mangle)]
pub extern "C" fn get_user_info_binded(
    server_url: *const c_char,
    email: *const c_char,
    password: *const c_char,
    disk_key_path: *const c_char,
    out_key_pair: *mut PkKeyPair,
    out_password_hash: *mut c_char,
    out_password_hash_capacity: usize,
    out_user_id: *mut i64,
    out_error: *mut c_char,
    out_error_len: usize,
) -> i32 {
    ffi_catch_unwind_wrapper(|| unsafe {
        get_user_info_internal(
            server_url,
            email,
            password,
            disk_key_path,
            out_key_pair,
            out_password_hash,
            out_password_hash_capacity,
            out_user_id,
            out_error,
            out_error_len,
        )
    })
}

unsafe fn get_user_info_internal(
    server_url: *const c_char,
    email: *const c_char,
    password: *const c_char,
    disk_key_path: *const c_char,
    out_key_pair: *mut PkKeyPair,
    out_password_hash: *mut c_char,
    out_password_hash_capacity: usize,
    out_user_id: *mut i64,
    out_error: *mut c_char,
    out_error_len: usize,
) -> i32 {
    if server_url.is_null()
        || email.is_null()
        || password.is_null()
        || disk_key_path.is_null()
        || out_key_pair.is_null()
        || out_password_hash.is_null()
        || out_user_id.is_null()
    {
        return -1;
    }
    if !out_key_pair.is_aligned() || !out_user_id.is_aligned() {
        return -1;
    }
    if !out_error.is_null() && out_error_len < 512 {
        return -2;
    }

    unsafe {
        let server_url_a = if let Ok(x) = CStr::from_ptr(server_url).to_str() {
            x
        } else {
            return -3;
        };
        let email_a = if let Ok(x) = CStr::from_ptr(email).to_str() {
            x
        } else {
            return -3;
        };
        let password_a = if let Ok(x) = CStr::from_ptr(password).to_str() {
            // yup password in plaintext. the original behaviour alr did that though, so...
            x
        } else {
            return -3;
        };
        let disk_key_path_a = if let Ok(x) = CStr::from_ptr(disk_key_path).to_str() {
            Path::new(x)
        } else {
            return -3;
        };

        match get_user_info(server_url_a, email_a, password_a, disk_key_path_a) {
            Ok((key_pair, password_hash, user_id)) => {
                let password_hash_length = password_hash.len();
                if out_password_hash_capacity < password_hash_length + 1 {
                    return -4;
                }

                *out_key_pair = key_pair;
                std::ptr::copy_nonoverlapping(
                    password_hash.as_ptr(),
                    out_password_hash.cast::<u8>(), // use c_char* in function signatures so that cbindgen emits char*, but a lot of the builtin byte-level APIs accept u8, and I think there's some platform inconsistencies w/ i8 vs u8
                    password_hash_length,
                );
                out_password_hash.add(password_hash_length).write(0);
                out_user_id.write(user_id);

                0
            }
            Err(ApiCallError::PasswordFail) => {
                if !out_error.is_null() {
                    const PASSWORD_ERROR_TEXT: [u8; 60] =
                        *b"Could not authenticate: Email/password don't match records.\0";

                    std::ptr::copy_nonoverlapping(
                        PASSWORD_ERROR_TEXT.as_ptr(),
                        out_error.cast::<u8>(),
                        PASSWORD_ERROR_TEXT.len(),
                    );
                }
                -5
            },
            Err(ApiCallError::OtherWithDetails(e)) => {
                if !out_error.is_null() {
                    let error_message = format!("{}", e);
                    let error_message_bytes: Box<[u8]> = error_message.bytes().collect();

                    let error_message_len = error_message_bytes.len().min(out_error_len - 1);

                    std::ptr::copy_nonoverlapping(
                        error_message_bytes.as_ptr(),
                        out_error.cast::<u8>(),
                        error_message_len,
                    );

                    out_error
                        .cast::<u8>()
                        .add(error_message_len)
                        .write('\0' as u8);
                }

                -6
            }
            Err(_) => -7, // also covers EmailTooShort
        }
    }
}

/// Registers a new user.  
///
/// # Arguments  
///
/// * `server_url` - The URL of the server
/// * `email` - The email of the user
/// * `password` - The password of the user. Can be an empty string (e.g "\0").
/// * `disk_key_path` - The path to the disk key directory  
///
/// # Returns  
///
/// Error codes:
/// * `-1` - Parameter error (null pointer).
/// * `-2` - Internal casting errors.
/// * `-3` - Internal library errors.
/// * `-4` - Email too short, must be at least of length 8.
/// * `-67` (`ERR_PANIC`) - Caught panic.  
#[unsafe(no_mangle)]
pub extern "C" fn register_binded(
    server_url: *const c_char,
    email: *const c_char,
    password: *const c_char,
    disk_key_path: *const c_char,
) -> i32 {
    ffi_catch_unwind_wrapper(|| unsafe {
        register_internal(server_url, email, password, disk_key_path)
    })
}

unsafe fn register_internal(
    server_url: *const c_char,
    email: *const c_char,
    password: *const c_char,
    disk_key_path: *const c_char,
) -> i32 {
    if server_url.is_null() || email.is_null() || password.is_null() || disk_key_path.is_null() {
        return -1;
    }

    unsafe {
        let server_url = if let Ok(x) = CStr::from_ptr(server_url).to_str() {
            x
        } else {
            return -2;
        };
        let email = if let Ok(x) = CStr::from_ptr(email).to_str() {
            x
        } else {
            return -2;
        };
        let password = if let Ok(x) = CStr::from_ptr(password).to_str() {
            x
        } else {
            return -2;
        };
        let disk_key_path = if let Ok(x) = CStr::from_ptr(disk_key_path).to_str() {
            Path::new(x)
        } else {
            return -2;
        };

        match crate::register(server_url, email, password, disk_key_path) {
            Ok(()) => 0,
            Err(e) if matches!(e.downcast_ref::<ApiCallError>(), Some(ApiCallError::EmailTooShort)) => -4,
            Err(_) => -3,
        }
    }
}

/// Downloads a file and saves it to the required output path or stdout.  
///
/// # Arguments  
///
/// * `server_url` - The URL of the server
/// * `email` - The email of the user
/// * `encoded_password` - The encoded password of the user
/// * `kp` - The user's key pair handle
/// * `file_id` - The ID of the file to download
/// * `output` - The path to save the file to
/// * `stdout` - Whether to output to stdout  
///
/// # Returns  
///
/// Error codes:
/// * `-1` - Parameter error (null pointers or misaligned key pair).
/// * `-2` - Internal casting errors.
/// * `-3` - Internal library errors.
/// * `-67` (`ERR_PANIC`) - Caught panic.  
#[unsafe(no_mangle)]
pub extern "C" fn download_binded(
    server_url: *const c_char,
    email: *const c_char,
    encoded_password: *const c_char,
    kp: *const PkKeyPair,
    file_id: i64,
    output: *const c_char,
    stdout: bool,
) -> i32 {
    ffi_catch_unwind_wrapper(|| unsafe {
        download_internal(
            server_url,
            email,
            encoded_password,
            kp,
            file_id,
            output,
            stdout,
        )
    })
}

unsafe fn download_internal(
    server_url: *const c_char,
    email: *const c_char,
    encoded_password: *const c_char,
    kp: *const PkKeyPair,
    file_id: i64,
    output: *const c_char,
    stdout: bool,
) -> i32 {
    if server_url.is_null()
        || email.is_null()
        || encoded_password.is_null()
        || kp.is_null()
        || output.is_null()
    {
        return -1;
    }
    if !kp.is_aligned() {
        return -1;
    }

    unsafe {
        let server_url = if let Ok(x) = CStr::from_ptr(server_url).to_str() {
            x
        } else {
            return -2;
        };
        let email = if let Ok(x) = CStr::from_ptr(email).to_str() {
            x
        } else {
            return -2;
        };
        let encoded_password = if let Ok(x) = CStr::from_ptr(encoded_password).to_str() {
            x
        } else {
            return -2;
        };
        let output = if let Ok(x) = CStr::from_ptr(output).to_str() {
            PathBuf::from(x)
        } else {
            return -2;
        };

        match crate::download(
            server_url,
            email,
            encoded_password,
            &*kp,
            file_id,
            Some(output),
            stdout,
        ) {
            Ok(()) => 0,
            Err(_) => -3,
        }
    }
}

/// Uploads a file and returns its ID through an output parameter.  
///
/// # Arguments  
///
/// * `server_url` - The URL of the server
/// * `email` - The email of the user
/// * `encoded_password` - The encoded password of the user
/// * `kp` - The user's key pair handle
/// * `file_path` - The path of the file to upload
/// * `file_name` - The file name to use on the server
/// * `emails` - The recipient email string pointers
/// * `email_count` - The number of recipient email pointers
/// * `out_file_id` - Ensure this isn't null and is aligned  
///
/// # Returns  
///
/// Error codes:
/// * `-1` - Parameter error (null pointers or misaligned pointers).
/// * `-2` - Internal casting errors.
/// * `-3` - Internal library errors.
/// * `-4` - Could not establish connection to WebSocket server.
/// * `-67` (`ERR_PANIC`) - Caught panic.  
#[unsafe(no_mangle)]
pub extern "C" fn upload_binded(
    server_url: *const c_char,
    email: *const c_char,
    encoded_password: *const c_char,
    kp: *const PkKeyPair,
    file_path: *const c_char,
    file_name: *const c_char,
    emails: *const *const c_char,
    email_count: usize,
    out_file_id: *mut i64,
) -> i32 {
    ffi_catch_unwind_wrapper(|| unsafe {
        upload_internal(
            server_url,
            email,
            encoded_password,
            kp,
            file_path,
            file_name,
            emails,
            email_count,
            out_file_id,
        )
    })
}

unsafe fn upload_internal(
    server_url: *const c_char,
    email: *const c_char,
    encoded_password: *const c_char,
    kp: *const PkKeyPair,
    file_path: *const c_char,
    file_name: *const c_char,
    emails: *const *const c_char,
    email_count: usize,
    out_file_id: *mut i64,
) -> i32 {
    if server_url.is_null()
        || email.is_null()
        || encoded_password.is_null()
        || kp.is_null()
        || file_path.is_null()
        || file_name.is_null()
        || out_file_id.is_null()
        || (email_count > 0 && emails.is_null())
    {
        return -1;
    }
    if !kp.is_aligned() || !out_file_id.is_aligned() || (!emails.is_null() && !emails.is_aligned())
    {
        return -1;
    }

    unsafe {
        let server_url = if let Ok(x) = CStr::from_ptr(server_url).to_str() {
            x
        } else {
            return -2;
        };
        let email = if let Ok(x) = CStr::from_ptr(email).to_str() {
            x
        } else {
            return -2;
        };
        let encoded_password = if let Ok(x) = CStr::from_ptr(encoded_password).to_str() {
            x
        } else {
            return -2;
        };
        let file_path = if let Ok(x) = CStr::from_ptr(file_path).to_str() {
            x
        } else {
            return -2;
        };
        let file_name = if let Ok(x) = CStr::from_ptr(file_name).to_str() {
            x
        } else {
            return -2;
        };
        let mut emails_a = Vec::with_capacity(email_count);
        for i in 0..email_count {
            let email = *emails.add(i);
            if email.is_null() {
                return -1;
            }
            if let Ok(x) = CStr::from_ptr(email).to_str() {
                emails_a.push(x.to_string());
            } else {
                return -2;
            }
        }
        let file = match File::open(file_path) {
            Ok(file) => file,
            Err(_) => return -3,
        };

        match crate::upload(
            server_url,
            email,
            encoded_password,
            &*kp,
            file,
            file_name,
            None,
            emails_a,
        ) {
            Ok(file_id) => {
                out_file_id.write(file_id);
                0
            }
            Err(err_box) => {
                if let Some(e) = err_box.downcast_ref::<std::io::Error>() {
                    if e.kind() == std::io::ErrorKind::Unsupported {
                        return -4;
                    }
                };
                -3
            }
        }
    }
}

/// Lists files the user can access and writes a null-terminated UTF-8 JSON `FileInfos` value.  
///
/// # Arguments  
///
/// * `server_url` - The URL of the server.
/// * `email` - The email of the user.
/// * `encoded_password` - The encoded password hash of the user.
/// * `file_start_offset` - The zero-based index to start at, in ascending file ID order.
/// * `out_file_infos_capacity` - The buffer capacity in bytes, including space for the null terminator.  
///
/// Out params:
/// * `out_file_infos` - The caller-owned buffer for the JSON result.
/// * `out_total_files` - The total file count before applying the offset.
/// * `out_provided_files` - The number of complete entries written to the buffer.  
///
/// # Returns  
///
/// Error codes:
/// * `-1` - Parameter error (null pointers, misaligned count pointers, or an invalid offset).
/// * `-2` - An input string is not valid UTF-8.
/// * `-3` - Failed to fetch or serialize the file list.
/// * `-4` - The output buffer is smaller than the 13 bytes needed for an empty result and its null terminator.
/// * `-5` - The server rejected the email or password hash.
/// * `-67` (`ERR_PANIC`) - Caught panic.  
///
/// # Notes
/// 
/// Advance the offset by `out_provided_files` to request the next batch.
/// An empty batch is `{"files":[]}`. If `out_provided_files` is `0` and the offset is less than `out_total_files`, retry with a larger buffer.  
/// 
/// Non-null input string pointers must point to null-terminated strings.
/// The caller must provide a writable buffer of at least `out_file_infos_capacity` bytes and two aligned `i64` outputs.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn list_files_binded(
    server_url: *const c_char,
    email: *const c_char,
    encoded_password: *const c_char,
    file_start_offset: i64,
    out_file_infos: *mut c_char,
    out_file_infos_capacity: usize,
    out_total_files: *mut i64,
    out_provided_files: *mut i64,
) -> i32 {
    ffi_catch_unwind_wrapper(|| unsafe {
        list_files_internal(
            server_url,
            email,
            encoded_password,
            file_start_offset,
            out_file_infos,
            out_file_infos_capacity,
            out_total_files,
            out_provided_files,
        )
    })
}

unsafe fn list_files_internal(
    server_url: *const c_char,
    email: *const c_char,
    encoded_password: *const c_char,
    file_start_offset: i64,
    out_file_infos: *mut c_char,
    out_file_infos_capacity: usize,
    out_total_files: *mut i64,
    out_provided_files: *mut i64,
) -> i32 {
    const JSON_PREFIX: &[u8] = br#"{"files":["#;
    const JSON_SUFFIX: &[u8] = b"]}\0";

    if server_url.is_null()
        || email.is_null()
        || encoded_password.is_null()
        || out_file_infos.is_null()
        || out_total_files.is_null()
        || out_provided_files.is_null()
        || file_start_offset < 0
    {
        return -1;
    }
    if !out_total_files.is_aligned() || !out_provided_files.is_aligned() {
        return -1;
    }
    if out_file_infos_capacity < JSON_PREFIX.len() + JSON_SUFFIX.len() {
        return -4;
    }

    unsafe {
        let server_url = if let Ok(x) = CStr::from_ptr(server_url).to_str() {
            x
        } else {
            return -2;
        };
        let email = if let Ok(x) = CStr::from_ptr(email).to_str() {
            x
        } else {
            return -2;
        };
        let encoded_password = if let Ok(x) = CStr::from_ptr(encoded_password).to_str() {
            x
        } else {
            return -2;
        };
        let file_start_offset = match usize::try_from(file_start_offset) {
            Ok(x) => x,
            Err(_) => return -1,
        };
        let mut file_infos = match crate::list_files(server_url, email, encoded_password) {
            Ok(x) => x,
            Err(e) if matches!(e.downcast_ref::<ApiCallError>(), Some(ApiCallError::PasswordFail)) => {
                return -5;
            }
            Err(_) => return -3,
        };
        let total_files = match i64::try_from(file_infos.files.len()) {
            Ok(x) => x,
            Err(_) => return -3,
        };

        file_infos.files.sort_unstable_by_key(|file_info| file_info.file_id);
        let mut json = JSON_PREFIX.to_vec();
        let mut provided_files = 0_i64;
        for file_info in file_infos.files.into_iter().skip(file_start_offset) {
            let file_info_json = match serde_json::to_vec(&file_info) {
                Ok(x) => x,
                Err(_) => return -3,
            };
            let separator_length = usize::from(provided_files > 0);
            let required_capacity = match json
                .len()
                .checked_add(separator_length)
                .and_then(|x| x.checked_add(file_info_json.len()))
                .and_then(|x| x.checked_add(JSON_SUFFIX.len()))
            {
                Some(x) => x,
                None => return -3,
            };
            if required_capacity > out_file_infos_capacity {
                break;
            }
            if provided_files > 0 {
                json.push(b',');
            }
            json.extend_from_slice(&file_info_json);
            provided_files += 1;
        }

        json.extend_from_slice(JSON_SUFFIX);
        std::ptr::copy_nonoverlapping(json.as_ptr(), out_file_infos.cast::<u8>(), json.len());
        out_total_files.write(total_files);
        out_provided_files.write(provided_files);

        0
    }
}
