use std::{io, path::Path, ptr, sync::Arc};

use jni::objects::{GlobalRef, JByteArray, JClass, JObject, JString, JValue};
use jni::sys::{jboolean, jbyteArray, jint, jlong, jstring};
use jni::{JNIEnv, JavaVM};
use rns_tun::SocketProtector;

use crate::session::AppliedTunConfig;

struct JavaProtector {
    vm: JavaVM,
    service: GlobalRef,
}

impl SocketProtector for JavaProtector {
    fn protect(&self, fd: std::os::fd::RawFd) -> io::Result<()> {
        let mut env = self.vm.attach_current_thread().map_err(jni_io)?;
        let protected = env
            .call_method(self.service.as_obj(), "protect", "(I)Z", &[JValue::Int(fd)])
            .and_then(|value| value.z())
            .map_err(jni_io)?;
        protected.then_some(()).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::PermissionDenied,
                "VpnService.protect rejected an underlay socket",
            )
        })
    }
}

fn jni_io(error: jni::errors::Error) -> io::Error {
    io::Error::other(error.to_string())
}

fn string_arg(env: &mut JNIEnv<'_>, value: &JString<'_>) -> jni::errors::Result<String> {
    env.get_string(value).map(Into::into)
}

fn throw(env: &mut JNIEnv<'_>, class: &str, message: impl ToString) {
    let _ = env.throw_new(class, message.to_string());
}

fn java_string(env: &mut JNIEnv<'_>, value: impl Into<String>) -> jstring {
    match env.new_string(value.into()) {
        Ok(value) => value.into_raw(),
        Err(error) => {
            throw(env, "java/lang/RuntimeException", error);
            ptr::null_mut()
        }
    }
}

fn java_bytes(env: &mut JNIEnv<'_>, value: &[u8]) -> jbyteArray {
    match env.byte_array_from_slice(value) {
        Ok(value) => value.into_raw(),
        Err(error) => {
            throw(env, "java/lang/RuntimeException", error);
            ptr::null_mut()
        }
    }
}

fn required_string(env: &mut JNIEnv<'_>, value: &JString<'_>, class: &str) -> Option<String> {
    match string_arg(env, value) {
        Ok(value) => Some(value),
        Err(error) => {
            throw(env, class, error);
            None
        }
    }
}

#[no_mangle]
pub extern "system" fn Java_com_lelloman_rntun_NativeBridge_nativeCreate(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    config: JString<'_>,
) -> jlong {
    let Some(config) = required_string(&mut env, &config, "java/lang/IllegalArgumentException")
    else {
        return 0;
    };
    match crate::create_handle(config) {
        Ok(handle) => handle as jlong,
        Err(error) => {
            throw(&mut env, "java/lang/IllegalArgumentException", error);
            0
        }
    }
}

#[no_mangle]
pub extern "system" fn Java_com_lelloman_rntun_NativeBridge_nativeStart(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    handle: jlong,
    service: JObject<'_>,
) {
    let result = env
        .new_global_ref(service)
        .and_then(|service| env.get_java_vm().map(|vm| (service, vm)));
    let (service, vm) = match result {
        Ok(value) => value,
        Err(error) => {
            throw(&mut env, "java/io/IOException", error);
            return;
        }
    };
    let protector = Arc::new(JavaProtector { vm, service });
    if let Err(error) = crate::install_protector_object(handle as u64, protector)
        .and_then(|_| crate::start_handle(handle as u64))
    {
        throw(&mut env, "java/io/IOException", error);
    }
}

#[no_mangle]
pub extern "system" fn Java_com_lelloman_rntun_NativeBridge_nativePollEvent(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    handle: jlong,
) -> jstring {
    match crate::poll_event(handle as u64) {
        Ok(Some(event)) => java_string(&mut env, event),
        Ok(None) => ptr::null_mut(),
        Err(error) => {
            throw(&mut env, "java/io/IOException", error);
            ptr::null_mut()
        }
    }
}

#[no_mangle]
pub extern "system" fn Java_com_lelloman_rntun_NativeBridge_nativeStatus(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    handle: jlong,
) -> jstring {
    match crate::status_json(handle as u64) {
        Ok(status) => java_string(&mut env, status),
        Err(error) => {
            throw(&mut env, "java/io/IOException", error);
            ptr::null_mut()
        }
    }
}

#[no_mangle]
pub extern "system" fn Java_com_lelloman_rntun_NativeBridge_nativeAttachTun(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    handle: jlong,
    fd: jint,
    applied: JString<'_>,
) {
    let parsed = required_string(&mut env, &applied, "java/lang/IllegalArgumentException")
        .and_then(|value| serde_json::from_str::<AppliedTunConfig>(&value).ok());
    let Some(parsed) = parsed else {
        throw(
            &mut env,
            "java/lang/IllegalArgumentException",
            "invalid applied TUN configuration",
        );
        return;
    };
    if let Err(error) = crate::attach_duplicated_tun(handle as u64, fd, Some(parsed)) {
        throw(&mut env, "java/io/IOException", error);
    }
}

#[no_mangle]
pub extern "system" fn Java_com_lelloman_rntun_NativeBridge_nativeStop(
    _env: JNIEnv<'_>,
    _class: JClass<'_>,
    handle: jlong,
) -> jboolean {
    crate::destroy_handle(handle as u64) as jboolean
}

#[no_mangle]
pub extern "system" fn Java_com_lelloman_rntun_NativeBridge_nativeEnsureIdentity(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    path: JString<'_>,
) -> jstring {
    let Some(path) = required_string(&mut env, &path, "java/io/IOException") else {
        return ptr::null_mut();
    };
    match crate::ensure_identity(Path::new(&path)) {
        Ok(hash) => java_string(&mut env, hash),
        Err(error) => {
            throw(&mut env, "java/io/IOException", error);
            ptr::null_mut()
        }
    }
}

#[no_mangle]
pub extern "system" fn Java_com_lelloman_rntun_NativeBridge_nativeExportIdentity(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    path: JString<'_>,
) -> jbyteArray {
    let Some(path) = required_string(&mut env, &path, "java/io/IOException") else {
        return ptr::null_mut();
    };
    match crate::export_identity(Path::new(&path)) {
        Ok(bytes) => java_bytes(&mut env, &bytes),
        Err(error) => {
            throw(&mut env, "java/io/IOException", error);
            ptr::null_mut()
        }
    }
}

#[no_mangle]
pub extern "system" fn Java_com_lelloman_rntun_NativeBridge_nativeImportIdentity(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    path: JString<'_>,
    bytes: JByteArray<'_>,
) -> jstring {
    let Some(path) = required_string(&mut env, &path, "java/io/IOException") else {
        return ptr::null_mut();
    };
    let bytes = match env.convert_byte_array(bytes) {
        Ok(value) => value,
        Err(error) => {
            throw(&mut env, "java/io/IOException", error);
            return ptr::null_mut();
        }
    };
    match crate::import_identity(Path::new(&path), &bytes) {
        Ok(hash) => java_string(&mut env, hash),
        Err(error) => {
            throw(&mut env, "java/io/IOException", error);
            ptr::null_mut()
        }
    }
}

fn bundle_transform(
    env: &mut JNIEnv<'_>,
    bundle_type: JString<'_>,
    input: JByteArray<'_>,
    password: JString<'_>,
    transform: fn(&str, &[u8], &str) -> io::Result<Vec<u8>>,
) -> jbyteArray {
    let Some(bundle_type) =
        required_string(env, &bundle_type, "java/security/GeneralSecurityException")
    else {
        return ptr::null_mut();
    };
    let Some(password) = required_string(env, &password, "java/security/GeneralSecurityException")
    else {
        return ptr::null_mut();
    };
    let input = match env.convert_byte_array(input) {
        Ok(value) => value,
        Err(error) => {
            throw(env, "java/security/GeneralSecurityException", error);
            return ptr::null_mut();
        }
    };
    match transform(&bundle_type, &input, &password) {
        Ok(bytes) => java_bytes(env, &bytes),
        Err(error) => {
            throw(env, "java/security/GeneralSecurityException", error);
            ptr::null_mut()
        }
    }
}

#[no_mangle]
pub extern "system" fn Java_com_lelloman_rntun_NativeBridge_nativeEncryptBundle(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    bundle_type: JString<'_>,
    plaintext: JByteArray<'_>,
    password: JString<'_>,
) -> jbyteArray {
    bundle_transform(
        &mut env,
        bundle_type,
        plaintext,
        password,
        crate::bundle::encrypt,
    )
}

#[no_mangle]
pub extern "system" fn Java_com_lelloman_rntun_NativeBridge_nativeDecryptBundle(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    bundle_type: JString<'_>,
    encoded: JByteArray<'_>,
    password: JString<'_>,
) -> jbyteArray {
    bundle_transform(
        &mut env,
        bundle_type,
        encoded,
        password,
        crate::bundle::decrypt,
    )
}

#[no_mangle]
pub extern "system" fn Java_com_lelloman_rntun_NativeBridge_nativeValidateNodeConfig(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    config: JString<'_>,
    full_tunnel: jboolean,
) -> jstring {
    let Some(config) = required_string(&mut env, &config, "java/lang/IllegalArgumentException")
    else {
        return ptr::null_mut();
    };
    match crate::validate_node_config_text(&config, full_tunnel != 0) {
        Ok(()) => ptr::null_mut(),
        Err(error) => java_string(&mut env, error.to_string()),
    }
}
