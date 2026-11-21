use std::{
    ffi::{CStr, CString, c_char},
    fs::File,
    path::{Path, PathBuf},
};

use corelib::client::PkKeyPair;

use crate::get_user_info;

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

/// Decrypts the user's private key and fetches their user info from the server  
///
/// # Arguments  
///
/// * `server_url` - The URL of the server
/// * `email` - The email of the user
/// * `password` - The password of the user
/// * `disk_key_path` - The path to the disk key directory  
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
/// * `-2` - Internal casting errors.
/// * `-3` - Internal library errors.
/// * `-4` - Password hash buffer is too small.  
///
/// Out params:  
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

    unsafe {
        let server_url_a = if let Ok(x) = CStr::from_ptr(server_url).to_str() {
            x
        } else {
            return -2;
        };
        let email_a = if let Ok(x) = CStr::from_ptr(email).to_str() {
            x
        } else {
            return -2;
        };
        let password_a = if let Ok(x) = CStr::from_ptr(password).to_str() {
            // yup password in plaintext. the original behaviour alr did that though, so...
            x
        } else {
            return -2;
        };
        let disk_key_path_a = if let Ok(x) = CStr::from_ptr(disk_key_path).to_str() {
            Path::new(x)
        } else {
            return -2;
        };

        match get_user_info(server_url_a, email_a, password_a, disk_key_path_a) {
            Ok((key_pair, password_hash, user_id)) => {
                let password_hash_length = password_hash.len();
                if out_password_hash_capacity < password_hash_length + 1 {
                    return -4;
                }

                out_key_pair.write(key_pair);
                std::ptr::copy_nonoverlapping(
                    password_hash.as_ptr(),
                    out_password_hash.cast::<u8>(), // use c_char* in function signatures so that cbindgen emits char*, but a lot of the builtin byte-level APIs accept u8, and I think there's some platform inconsistencies w/ i8 vs u8
                    password_hash_length,
                );
                out_password_hash.add(password_hash_length).write(0);
                out_user_id.write(user_id);

                0
            }

            Err(_) => -3,
        }
    }
}

/// Registers a new user.  
///
/// # Arguments  
///
/// * `server_url` - The URL of the server
/// * `email` - The email of the user
/// * `password` - The password of the user
/// * `disk_key_path` - The path to the disk key directory  
///
/// # Returns  
///
/// Error codes:
/// * `-1` - Parameter error (null pointer).
/// * `-2` - Internal casting errors.
/// * `-3` - Internal library errors.
#[unsafe(no_mangle)]
pub extern "C" fn register_binded(
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
            Err(_) => -3,
        }
    }
}
