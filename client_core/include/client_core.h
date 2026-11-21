#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

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
 * * `server_url` - The URL of the server
 * * `email` - The email of the user
 * * `password` - The password of the user
 * * `disk_key_path` - The path to the disk key directory  
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
 * * `-2` - Internal casting errors.
 * * `-3` - Internal library errors.
 * * `-4` - Password hash buffer is too small.  
 * 
 * Out params:  
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
                             int64_t *out_user_id);

/**
 * Registers a new user.  
 *
 * # Arguments  
 *
 * * `server_url` - The URL of the server
 * * `email` - The email of the user
 * * `password` - The password of the user
 * * `disk_key_path` - The path to the disk key directory  
 *
 * # Returns  
 *
 * Error codes:
 * * `-1` - Parameter error (null pointer).
 * * `-2` - Internal casting errors.
 * * `-3` - Internal library errors.
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
