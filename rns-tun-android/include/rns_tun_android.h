#ifndef RNS_TUN_ANDROID_H
#define RNS_TUN_ANDROID_H

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef bool (*rntun_protect_callback)(int fd, void *user_data);

uint64_t rntun_android_create(const char *config_json);
int rntun_android_set_protector(uint64_t handle,
                                rntun_protect_callback callback,
                                void *user_data);
int rntun_android_start(uint64_t handle);
/* Poll JSON events; see Rust API docs for sizing semantics. */
intptr_t rntun_android_poll_event(uint64_t handle, char *output, uintptr_t capacity);
/* Rust takes ownership and closes fd, including after a successful call. */
int rntun_android_attach_tun_owned(uint64_t handle, int fd);
/* Rust duplicates fd; the caller keeps ownership of the original. */
int rntun_android_attach_tun_dup(uint64_t handle, int fd);
/* Preferred API: confirms the exact applied address/routes/DNS/MTU as JSON. */
int rntun_android_attach_tun_dup_v2(uint64_t handle, int fd,
                                    const char *applied_json);
bool rntun_android_destroy(uint64_t handle);

#ifdef __cplusplus
}
#endif

#endif
