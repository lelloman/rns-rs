//! BLE NUS (Nordic UART Service) GATT server for ESP32-S3.
//!
//! Provides a serial-like interface over BLE using the standard NUS UUIDs.
//! The phone writes to the RX characteristic and the device sends notifications
//! on the TX characteristic.

use std::ffi::CString;
use std::io;
use std::sync::atomic::{AtomicBool, AtomicU16, Ordering};
use std::sync::{LazyLock, Mutex};
use std::time::{Duration, Instant};

use esp_idf_sys::*;
use rns_esp32::ble_buffer::BleRxBuffer;

// Nordic UART Service UUIDs (128-bit, little-endian for NimBLE)
// Service: 6E400001-B5A3-F393-E0A9-E50E24DCCA9E
const NUS_SERVICE_UUID128: [u8; 16] = [
    0x9E, 0xCA, 0xDC, 0x24, 0x0E, 0xE5, 0xA9, 0xE0, 0x93, 0xF3, 0xA3, 0xB5, 0x01, 0x00, 0x40, 0x6E,
];

// RX Characteristic: 6E400002-B5A3-F393-E0A9-E50E24DCCA9E (phone writes here)
const NUS_RX_UUID128: [u8; 16] = [
    0x9E, 0xCA, 0xDC, 0x24, 0x0E, 0xE5, 0xA9, 0xE0, 0x93, 0xF3, 0xA3, 0xB5, 0x02, 0x00, 0x40, 0x6E,
];

// TX Characteristic: 6E400003-B5A3-F393-E0A9-E50E24DCCA9E (device notifies here)
const NUS_TX_UUID128: [u8; 16] = [
    0x9E, 0xCA, 0xDC, 0x24, 0x0E, 0xE5, 0xA9, 0xE0, 0x93, 0xF3, 0xA3, 0xB5, 0x03, 0x00, 0x40, 0x6E,
];

/// Default MTU before negotiation (BLE 4.2 minimum).
const DEFAULT_MTU: u16 = 23;

/// MTU we request during negotiation.
const PREFERRED_MTU: u16 = 247;

/// BLE NUS state. Accessed from NimBLE callbacks via static, so we use a global.
static BLE_STATE: BleState = BleState::new();

struct BleState {
    rx_buf: LazyLock<Mutex<BleRxBuffer>>,
    connected: AtomicBool,
    mtu: AtomicU16,
    conn_handle: AtomicU16,
    tx_val_handle: AtomicU16,
}

// Safety: NimBLE callbacks run on the NimBLE host task. We use Mutex for buffer
// access and atomics for flags/handles.
unsafe impl Sync for BleState {}

impl BleState {
    const fn new() -> Self {
        Self {
            rx_buf: LazyLock::new(|| Mutex::new(BleRxBuffer::default())),
            connected: AtomicBool::new(false),
            mtu: AtomicU16::new(DEFAULT_MTU),
            conn_handle: AtomicU16::new(0xFFFF),
            tx_val_handle: AtomicU16::new(0),
        }
    }
}

/// Initialize the NimBLE host stack and register the NUS GATT service.
///
/// Must be called once at startup before `start_advertising()`.
pub fn init(device_name: &str) {
    ::log::info!("BLE NUS: initializing NimBLE");

    unsafe {
        // Initialize NimBLE (controller + host stack)
        let rc = nimble_port_init();
        if rc != 0 {
            ::log::error!("BLE: nimble_port_init failed: {}", rc);
            return;
        }

        // Set device name
        let name = CString::new(device_name).unwrap();
        ble_svc_gap_device_name_set(name.as_ptr());

        // Initialize GAP and GATT services
        ble_svc_gap_init();
        ble_svc_gatt_init();

        // Register NUS GATT service
        register_nus_gatt_service();

        // Set preferred MTU
        let rc = ble_att_set_preferred_mtu(PREFERRED_MTU);
        if rc != 0 {
            ::log::warn!("BLE: failed to set preferred MTU: {}", rc);
        }

        // Configure NimBLE host
        let cfg = core::ptr::addr_of_mut!(ble_hs_cfg);
        (*cfg).sync_cb = Some(on_sync);
        (*cfg).reset_cb = Some(on_reset);

        // Security: no pairing required (open access)
        (*cfg).sm_io_cap = BLE_HS_IO_NO_INPUT_OUTPUT as u8;
        (*cfg).set_sm_bonding(0);
        (*cfg).set_sm_mitm(0);
        (*cfg).set_sm_sc(0);
        (*cfg).sm_our_key_dist = 0;
        (*cfg).sm_their_key_dist = 0;

        // Start NimBLE host task
        nimble_port_freertos_init(Some(nimble_host_task));
    }

    ::log::info!("BLE NUS: initialized");
}

/// Start BLE advertising with a timeout in seconds.
/// Returns immediately; advertising runs in the background.
pub fn start_advertising(timeout_secs: u16) {
    unsafe {
        let mut adv_fields: ble_hs_adv_fields = core::mem::zeroed();
        adv_fields.flags = (BLE_HS_ADV_F_DISC_GEN | BLE_HS_ADV_F_BREDR_UNSUP) as u8;
        adv_fields.set_uuids128_is_complete(1);

        let mut uuid = ble_uuid128_t {
            u: ble_uuid_t {
                type_: BLE_UUID_TYPE_128 as u8,
            },
            value: NUS_SERVICE_UUID128,
        };
        adv_fields.uuids128 = &mut uuid;
        adv_fields.num_uuids128 = 1;

        let rc = ble_gap_adv_set_fields(&adv_fields);
        if rc != 0 {
            ::log::error!("BLE: adv_set_fields failed: {}", rc);
            return;
        }

        // Set scan response with device name
        let mut rsp_fields: ble_hs_adv_fields = core::mem::zeroed();
        rsp_fields.set_name_is_complete(1);
        let name = ble_svc_gap_device_name();
        rsp_fields.name = name as *const u8;
        rsp_fields.name_len = strlen(name as *const _) as u8;

        let rc = ble_gap_adv_rsp_set_fields(&rsp_fields);
        if rc != 0 {
            ::log::error!("BLE: adv_rsp_set_fields failed: {}", rc);
            return;
        }

        let mut adv_params: ble_gap_adv_params = core::mem::zeroed();
        adv_params.conn_mode = BLE_GAP_CONN_MODE_UND as u8;
        adv_params.disc_mode = BLE_GAP_DISC_MODE_GEN as u8;

        // Duration in milliseconds, BLE_HS_FOREVER (0) = indefinite
        let duration_ms = if timeout_secs > 0 {
            (timeout_secs as i32) * 1000
        } else {
            0
        };

        let rc = ble_gap_adv_start(
            BLE_OWN_ADDR_PUBLIC as u8,
            core::ptr::null(),
            duration_ms,
            &adv_params,
            Some(gap_event_cb),
            core::ptr::null_mut(),
        );
        if rc != 0 {
            ::log::error!("BLE: adv_start failed: {}", rc);
            return;
        }

        ::log::info!("BLE NUS: advertising started ({}s timeout)", timeout_secs);
    }
}

/// Stop advertising.
pub fn stop_advertising() {
    unsafe {
        let _ = ble_gap_adv_stop();
    }
    ::log::info!("BLE NUS: advertising stopped");
}

/// Check if a peer is currently connected.
pub fn is_connected() -> bool {
    BLE_STATE.connected.load(Ordering::SeqCst)
}

/// Get the negotiated MTU payload size (MTU - 3).
fn effective_mtu() -> usize {
    let mtu = BLE_STATE.mtu.load(Ordering::SeqCst) as usize;
    if mtu > 3 {
        mtu - 3
    } else {
        20 // BLE 4.2 minimum payload
    }
}

/// Queue data for transmission to the connected peer via TX notifications.
/// Data is chunked to fit the negotiated MTU.
pub fn write(data: &[u8]) -> io::Result<()> {
    if !is_connected() {
        return Err(io::Error::new(
            io::ErrorKind::NotConnected,
            "BLE transport is not connected",
        ));
    }

    let chunk_size = effective_mtu();
    let conn = BLE_STATE.conn_handle.load(Ordering::SeqCst);
    let val_handle = BLE_STATE.tx_val_handle.load(Ordering::SeqCst);
    if val_handle == 0 {
        return Err(io::Error::new(
            io::ErrorKind::NotConnected,
            "BLE TX characteristic is not ready",
        ));
    }

    for chunk in data.chunks(chunk_size) {
        unsafe {
            let om = ble_hs_mbuf_from_flat(chunk.as_ptr() as *const _, chunk.len() as u16);
            if om.is_null() {
                ::log::warn!("BLE TX: mbuf alloc failed");
                return Err(io::Error::new(
                    io::ErrorKind::Other,
                    "BLE mbuf allocation failed",
                ));
            }

            let rc = ble_gatts_notify_custom(conn, val_handle, om);
            if rc != 0 {
                ::log::debug!("BLE TX: notify failed: {}", rc);
                return Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    format!("BLE notify failed: {rc}"),
                ));
            }
        }
    }

    Ok(())
}

/// Read available bytes from the RX buffer. Returns the number of bytes read.
pub fn read(buf: &mut [u8]) -> usize {
    let mut rx = BLE_STATE.rx_buf.lock().unwrap();
    rx.pop_into(buf)
}

/// Read with a timeout. Polls the RX buffer until data is available or timeout expires.
pub fn read_timeout(buf: &mut [u8], timeout: Duration) -> usize {
    let deadline = Instant::now() + timeout;
    loop {
        let n = read(buf);
        if n > 0 {
            return n;
        }
        if Instant::now() >= deadline || !is_connected() {
            return 0;
        }
        std::thread::sleep(Duration::from_millis(1));
    }
}

/// Disconnect the active connection.
pub fn disconnect() {
    let conn = BLE_STATE.conn_handle.load(Ordering::SeqCst);
    if conn != 0xFFFF {
        unsafe {
            let _ = ble_gap_terminate(conn, ble_error_codes_BLE_ERR_REM_USER_CONN_TERM as u8);
        }
    }
}

// --- NimBLE callbacks ---

/// GAP event callback. Handles connect, disconnect, advertising complete.
unsafe extern "C" fn gap_event_cb(event: *mut ble_gap_event, _arg: *mut core::ffi::c_void) -> i32 {
    let event = &*event;
    match event.type_ as u32 {
        BLE_GAP_EVENT_CONNECT => {
            let connect = &event.__bindgen_anon_1.connect;
            if connect.status == 0 {
                let conn = connect.conn_handle;
                BLE_STATE.conn_handle.store(conn, Ordering::SeqCst);
                BLE_STATE.connected.store(true, Ordering::SeqCst);
                BLE_STATE.mtu.store(DEFAULT_MTU, Ordering::SeqCst);
                // Request MTU exchange
                let _ = ble_att_set_preferred_mtu(PREFERRED_MTU);
                let _ = ble_gattc_exchange_mtu(conn, Some(mtu_exchange_cb), core::ptr::null_mut());
                ::log::info!("BLE: connected (handle={})", conn);
            } else {
                ::log::warn!("BLE: connect failed: {}", connect.status);
                // Restart advertising on failed connect
                start_advertising(30);
            }
        }
        BLE_GAP_EVENT_DISCONNECT => {
            BLE_STATE.connected.store(false, Ordering::SeqCst);
            BLE_STATE.conn_handle.store(0xFFFF, Ordering::SeqCst);
            // Clear RX buffer
            BLE_STATE.rx_buf.lock().unwrap().clear();
            ::log::info!("BLE: disconnected");
        }
        BLE_GAP_EVENT_ADV_COMPLETE => {
            ::log::info!("BLE: advertising complete");
        }
        BLE_GAP_EVENT_MTU => {
            let mtu_evt = &event.__bindgen_anon_1.mtu;
            let new_mtu = mtu_evt.value;
            BLE_STATE.mtu.store(new_mtu, Ordering::SeqCst);
            ::log::info!("BLE: MTU updated to {}", new_mtu);
        }
        _ => {}
    }
    0
}

/// MTU exchange callback.
unsafe extern "C" fn mtu_exchange_cb(
    conn_handle: u16,
    _error: *const ble_gatt_error,
    _mtu: u16,
    _arg: *mut core::ffi::c_void,
) -> i32 {
    let mtu = ble_att_mtu(conn_handle);
    BLE_STATE.mtu.store(mtu, Ordering::SeqCst);
    ::log::info!("BLE: MTU exchanged: {}", mtu);
    0
}

/// NimBLE host sync callback — called when the host and controller are in sync.
unsafe extern "C" fn on_sync() {
    // Use public address
    let _ = ble_hs_id_infer_auto(0, &mut 0u8 as *mut _);
    // TX_VAL_HANDLE is now populated by NimBLE (ble_gatts_start runs before sync)
    let tx_val_handle = core::ptr::addr_of!(TX_VAL_HANDLE).read();
    BLE_STATE
        .tx_val_handle
        .store(tx_val_handle, Ordering::SeqCst);
    ::log::info!("BLE: host synced, tx_val_handle={}", tx_val_handle);
}

/// NimBLE host reset callback.
unsafe extern "C" fn on_reset(reason: i32) {
    ::log::warn!("BLE: host reset, reason={}", reason);
}

/// NimBLE host task entry point.
unsafe extern "C" fn nimble_host_task(_param: *mut core::ffi::c_void) {
    nimble_port_run();
}

/// Storage for the TX characteristic value handle, populated by NimBLE during host sync.
static mut TX_VAL_HANDLE: u16 = 0;

// --- GATT service registration ---

/// GATT access callback for the RX characteristic (phone writes here).
unsafe extern "C" fn gatt_rx_access_cb(
    _conn_handle: u16,
    _attr_handle: u16,
    ctxt: *mut ble_gatt_access_ctxt,
    _arg: *mut core::ffi::c_void,
) -> i32 {
    let ctxt = &*ctxt;
    if ctxt.op as u32 == BLE_GATT_ACCESS_OP_WRITE_CHR {
        let om = ctxt.om;
        if !om.is_null() {
            let data_len = os_mbuf_len(om) as usize;
            if data_len > 0 {
                let mut buf = vec![0u8; data_len];
                let rc = ble_hs_mbuf_to_flat(
                    om,
                    buf.as_mut_ptr() as *mut _,
                    data_len as u16,
                    core::ptr::null_mut(),
                );
                if rc == 0 {
                    let mut rx = BLE_STATE.rx_buf.lock().unwrap();
                    if !rx.try_extend(&buf) {
                        ::log::warn!("BLE RX: dropping write because RX buffer is full");
                        return BLE_ATT_ERR_INSUFFICIENT_RES as i32;
                    }
                }
            }
        }
    }
    0
}

/// GATT access callback for the TX characteristic (device notifies here).
/// Read access returns empty — actual data is sent via notifications.
unsafe extern "C" fn gatt_tx_access_cb(
    _conn_handle: u16,
    _attr_handle: u16,
    ctxt: *mut ble_gatt_access_ctxt,
    _arg: *mut core::ffi::c_void,
) -> i32 {
    let ctxt = &*ctxt;
    if ctxt.op as u32 == BLE_GATT_ACCESS_OP_READ_CHR {
        // Return empty for read; data goes via notifications
        let empty: [u8; 0] = [];
        let rc = os_mbuf_append(ctxt.om, empty.as_ptr() as *const _, 0);
        if rc != 0 {
            return BLE_ATT_ERR_INSUFFICIENT_RES as i32;
        }
    }
    0
}

/// Register the NUS GATT service with NimBLE.
///
/// This sets up the service with RX (write) and TX (notify) characteristics.
unsafe fn register_nus_gatt_service() {
    // We need static storage for the GATT service definition because NimBLE
    // holds a pointer to it. Use a static mutable since this is called once.
    static mut GATT_SVCS: [ble_gatt_svc_def; 2] = unsafe { core::mem::zeroed() };
    static mut GATT_CHARS: [ble_gatt_chr_def; 3] = unsafe { core::mem::zeroed() };
    static mut SVC_UUID: ble_uuid128_t = unsafe { core::mem::zeroed() };
    static mut RX_UUID: ble_uuid128_t = unsafe { core::mem::zeroed() };
    static mut TX_UUID: ble_uuid128_t = unsafe { core::mem::zeroed() };

    SVC_UUID = ble_uuid128_t {
        u: ble_uuid_t {
            type_: BLE_UUID_TYPE_128 as u8,
        },
        value: NUS_SERVICE_UUID128,
    };
    RX_UUID = ble_uuid128_t {
        u: ble_uuid_t {
            type_: BLE_UUID_TYPE_128 as u8,
        },
        value: NUS_RX_UUID128,
    };
    TX_UUID = ble_uuid128_t {
        u: ble_uuid_t {
            type_: BLE_UUID_TYPE_128 as u8,
        },
        value: NUS_TX_UUID128,
    };

    // RX characteristic: phone writes here (write without response)
    GATT_CHARS[0] = ble_gatt_chr_def {
        uuid: core::ptr::addr_of!(RX_UUID) as *const ble_uuid_t,
        access_cb: Some(gatt_rx_access_cb),
        arg: core::ptr::null_mut(),
        descriptors: core::ptr::null_mut(),
        flags: (BLE_GATT_CHR_F_WRITE | BLE_GATT_CHR_F_WRITE_NO_RSP) as u16,
        min_key_size: 0,
        val_handle: core::ptr::null_mut(),
        cpfd: core::ptr::null_mut(),
    };

    // TX characteristic: device notifies here
    GATT_CHARS[1] = ble_gatt_chr_def {
        uuid: core::ptr::addr_of!(TX_UUID) as *const ble_uuid_t,
        access_cb: Some(gatt_tx_access_cb),
        arg: core::ptr::null_mut(),
        descriptors: core::ptr::null_mut(),
        flags: (BLE_GATT_CHR_F_NOTIFY | BLE_GATT_CHR_F_READ) as u16,
        min_key_size: 0,
        val_handle: core::ptr::addr_of_mut!(TX_VAL_HANDLE),
        cpfd: core::ptr::null_mut(),
    };

    // Terminator
    GATT_CHARS[2] = core::mem::zeroed();

    // NUS service
    GATT_SVCS[0] = ble_gatt_svc_def {
        type_: BLE_GATT_SVC_TYPE_PRIMARY as u8,
        uuid: core::ptr::addr_of!(SVC_UUID) as *const ble_uuid_t,
        includes: core::ptr::null_mut(),
        characteristics: core::ptr::addr_of!(GATT_CHARS[0]),
    };

    // Terminator
    GATT_SVCS[1] = core::mem::zeroed();

    let rc = ble_gatts_count_cfg(core::ptr::addr_of!(GATT_SVCS[0]));
    if rc != 0 {
        ::log::error!("BLE: gatts_count_cfg failed: {}", rc);
        return;
    }

    let rc = ble_gatts_add_svcs(core::ptr::addr_of!(GATT_SVCS[0]));
    if rc != 0 {
        ::log::error!("BLE: gatts_add_svcs failed: {}", rc);
        return;
    }

    ::log::info!("BLE NUS: GATT service registered");
}
