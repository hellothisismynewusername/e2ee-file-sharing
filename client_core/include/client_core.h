#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

#define ERR_PANIC -67

/**
 * In-memory only.
 */
typedef struct PkKeyPair PkKeyPair;

/**
 * Do *not* use this until initialized by one of the other exposed API functions; use this to create a handle to pass into exposed API functions.  
 *
 * Use `free_PkKeyPair()` to free `PkKeyPair`s.  
 *
 * # Returns  
 *
 * An opaque handle for `PkKeyPair`
 */
struct PkKeyPair *new_PkKeyPair(void);

/**
 * Use this to free `PkKeyPair`s.
 */
void free_PkKeyPair(struct PkKeyPair *ptr);

/**
 * Use this function to free strings allocated in rust code (as opposed to standard `free()`).
 */
void free_String(char *ptr);

/**
 * Decrypts the user's private key and fetches their user info from the server  
 *
 * # Arguments  
 *
 * * `server_url` - The URL of the server.
 * * `email` - The email of the user.
 * * `password` - The password of the user.
 * * `disk_key_path` - The path to the disk key directory.
 * * `out_error` - Optional, pass in null or pass in a pre-allocated buffer of at least `512` bytes.
 * * `out_error_len` - Max capacity of `out_error` should you choose to use it. Must be at least `512`.  
 *
 * Out params:
 * * `out_key_pair` - Use `new_PkKeyPair()` to get a `PkKeyPair` handle to pass in.
 * * `out_password_hash` - The buffer to receive the null-terminated password hash.
 * * `out_password_hash_capacity` - The size of the password hash buffer.
 * * `out_user_id` - Ensure this isn't null and also is aligned.  
 *
 * # Returns  
 *
 * Error codes:
 * * `-1` - Parameter error (null ptrs, `out_key_pair` or `out_user_id` isn't aligned).
 * * `-2` - Non-null `out_error` was passed in, but `out_error_len` capacity is not at least `512` bytes.
 * * `-3` - Internal casting errors
 * * `-4` - Password hash buffer is too small.
 * * `-5` - Email/password fail, writes to `out_error` if not null.
 * * `-6` - Other server fail, writes to `out_error` if not null.
 * * `-7` - Inexplicable other server fail, does not write to `out_error`.
 * * `-67` (`ERR_PANIC`) - Caught panic.  
 *
 * Good path out params:  
 *
 * A `PkKeyPair` opaque handle through `out_key_pair`, and the password hash and user id as the other mutable outputs.
 */
int32_t get_user_info_binded(const char *server_url,
                             const char *email,
                             const char *password,
                             const char *disk_key_path,
                             struct PkKeyPair *out_key_pair,
                             char *out_password_hash,
                             uintptr_t out_password_hash_capacity,
                             int64_t *out_user_id,
                             char *out_error,
                             uintptr_t out_error_len);

/**
 * Registers a new user.  
 *
 * # Arguments  
 *
 * * `server_url` - The URL of the server
 * * `email` - The email of the user
 * * `password` - The password of the user. Can be an empty string (e.g "\0").
 * * `disk_key_path` - The path to the disk key directory  
 *
 * # Returns  
 *
 * Error codes:
 * * `-1` - Parameter error (null pointer).
 * * `-2` - Internal casting errors.
 * * `-3` - Internal library errors.
 * * `-4` - Email too short, must be at least of length 8.
 * * `-67` (`ERR_PANIC`) - Caught panic.  
 */
int32_t register_binded(const char *server_url,
                        const char *email,
                        const char *password,
                        const char *disk_key_path);

/**
 * Downloads a file and saves it to the required output path or stdout.  
 *
 * # Arguments  
 *
 * * `server_url` - The URL of the server
 * * `email` - The email of the user
 * * `encoded_password` - The encoded password of the user
 * * `kp` - The user's key pair handle
 * * `file_id` - The ID of the file to download
 * * `output` - The path to save the file to
 * * `stdout` - Whether to output to stdout  
 *
 * # Returns  
 *
 * Error codes:
 * * `-1` - Parameter error (null pointers or misaligned key pair).
 * * `-2` - Internal casting errors.
 * * `-3` - Internal library errors.
 * * `-67` (`ERR_PANIC`) - Caught panic.  
 */
int32_t download_binded(const char *server_url,
                        const char *email,
                        const char *encoded_password,
                        const struct PkKeyPair *kp,
                        int64_t file_id,
                        const char *output,
                        bool stdout);

/**
 * Uploads a file and returns its ID through an output parameter.  
 *
 * # Arguments  
 *
 * * `server_url` - The URL of the server
 * * `email` - The email of the user
 * * `encoded_password` - The encoded password of the user
 * * `kp` - The user's key pair handle
 * * `file_path` - The path of the file to upload
 * * `file_name` - The file name to use on the server
 * * `emails` - The recipient email string pointers
 * * `email_count` - The number of recipient email pointers
 * * `out_file_id` - Ensure this isn't null and is aligned  
 *
 * # Returns  
 *
 * Error codes:
 * * `-1` - Parameter error (null pointers or misaligned pointers).
 * * `-2` - Internal casting errors.
 * * `-3` - Internal library errors.
 * * `-4` - Could not establish connection to WebSocket server.
 * * `-67` (`ERR_PANIC`) - Caught panic.  
 */
int32_t upload_binded(const char *server_url,
                      const char *email,
                      const char *encoded_password,
                      const struct PkKeyPair *kp,
                      const char *file_path,
                      const char *file_name,
                      const char *const *emails,
                      uintptr_t email_count,
                      int64_t *out_file_id);

/**
 * Lists files the user can access and writes a null-terminated UTF-8 JSON `FileInfos` value.  
 *
 * # Arguments  
 *
 * * `server_url` - The URL of the server.
 * * `email` - The email of the user.
 * * `encoded_password` - The encoded password hash of the user.
 * * `file_start_offset` - The zero-based index to start at, in ascending file ID order.
 * * `out_file_infos_capacity` - The buffer capacity in bytes, including space for the null terminator.  
 *
 * Out params:
 * * `out_file_infos` - The caller-owned buffer for the JSON result.
 * * `out_total_files` - The total file count before applying the offset.
 * * `out_provided_files` - The number of complete entries written to the buffer.  
 *
 * # Returns  
 *
 * Error codes:
 * * `-1` - Parameter error (null pointers, misaligned count pointers, or an invalid offset).
 * * `-2` - An input string is not valid UTF-8.
 * * `-3` - Failed to fetch or serialize the file list.
 * * `-4` - The output buffer is smaller than the 13 bytes needed for an empty result and its null terminator.
 * * `-5` - The server rejected the email or password hash.
 * * `-67` (`ERR_PANIC`) - Caught panic.  
 *
 * # Notes
 * 
 * Advance the offset by `out_provided_files` to request the next batch.
 * An empty batch is `{"files":[]}`. If `out_provided_files` is `0` and the offset is less than `out_total_files`, retry with a larger buffer.  
 * 
 * Non-null input string pointers must point to null-terminated strings.
 * The caller must provide a writable buffer of at least `out_file_infos_capacity` bytes and two aligned `i64` outputs.
 */
int32_t list_files_binded(const char *server_url,
                          const char *email,
                          const char *encoded_password,
                          int64_t file_start_offset,
                          char *out_file_infos,
                          uintptr_t out_file_infos_capacity,
                          int64_t *out_total_files,
                          int64_t *out_provided_files);
