//! Reticulum LoRa transport node firmware for Heltec WiFi LoRa 32 V3.
//!
//! Initializes hardware, generates/loads identity, starts SX1262 LoRa
//! interface, OLED display, and runs the Reticulum transport engine event loop.
//! Supports dual mode: standalone Reticulum node + RNode USB bridge.

mod ble;
mod button;
mod config;
mod display;
mod driver;
mod ifac;
mod lora;
mod rng;
mod rnode;
mod util;
mod version;

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc, Mutex};

use esp_idf_hal::gpio::{AnyIOPin, PinDriver};
use esp_idf_hal::i2c::{I2cConfig, I2cDriver};
use esp_idf_hal::peripherals::Peripherals;
use esp_idf_hal::spi::{SpiDriver, SpiDriverConfig};
use esp_idf_hal::uart::{self, UartDriver};
use esp_idf_hal::units::Hertz;
use esp_idf_svc::nvs::{EspDefaultNvsPartition, EspNvs, NvsDefault};

use rns_core::transport::types::{InterfaceId, TransportConfig};
use rns_crypto::identity::Identity;

use crate::util::hex;

const NVS_NAMESPACE: &str = "rns";
const NVS_KEY_IDENTITY: &str = "id_prv";

fn main() {
    // Initialize ESP-IDF logging and system
    esp_idf_svc::sys::link_patches();
    esp_idf_svc::log::EspLogger::initialize_default();
    log::info!("rns-esp32 starting ({})", version::FULL_VERSION);

    let peripherals = Peripherals::take().expect("failed to take peripherals");

    // Enable Vext (powers SX1262 + OLED on Heltec V3)
    let mut vext = PinDriver::output(AnyIOPin::from(peripherals.pins.gpio36)).expect("Vext pin");
    vext.set_low().expect("enable Vext"); // Active low on Heltec V3

    // Load or generate identity
    let nvs_partition = EspDefaultNvsPartition::take().expect("NVS partition");
    let identity = load_or_create_identity(&nvs_partition);
    let identity_hash = *identity.hash();
    let identity_hex = hex(&identity_hash);
    log::info!("Identity: {}", identity_hex);

    // Initialize OLED display
    let oled_rst = PinDriver::output(AnyIOPin::from(peripherals.pins.gpio21)).expect("OLED RST");
    let i2c_config = I2cConfig::new()
        .baudrate(Hertz(100_000))
        .sda_enable_pullup(true)
        .scl_enable_pullup(true);
    let i2c = I2cDriver::new(
        peripherals.i2c0,
        peripherals.pins.gpio17, // SDA
        peripherals.pins.gpio18, // SCL
        &i2c_config,
    )
    .expect("I2C driver init");

    let display_stats = Arc::new(Mutex::new(display::DisplayStats::new(identity_hex.clone())));

    if let Some(disp) = display::init(i2c, oled_rst) {
        let stats_clone = display_stats.clone();
        std::thread::Builder::new()
            .name("oled".into())
            .stack_size(8192)
            .spawn(move || {
                display::refresh_loop(disp, stats_clone);
            })
            .expect("failed to spawn display thread");
        log::info!("OLED display thread started");
    }

    // Initialize SPI for SX1262
    let spi_driver = SpiDriver::new(
        peripherals.spi2,
        peripherals.pins.gpio9,        // SCK
        peripherals.pins.gpio10,       // MOSI
        Some(peripherals.pins.gpio11), // MISO
        &SpiDriverConfig::default(),
    )
    .expect("SPI driver init");

    let cs = PinDriver::output(AnyIOPin::from(peripherals.pins.gpio8)).expect("CS pin");
    let rst = PinDriver::output(AnyIOPin::from(peripherals.pins.gpio12)).expect("RST pin");
    let busy = PinDriver::input(AnyIOPin::from(peripherals.pins.gpio13)).expect("BUSY pin");
    let dio1 = PinDriver::input(AnyIOPin::from(peripherals.pins.gpio14)).expect("DIO1 pin");

    // Initialize LoRa radio
    let (radio, writer) = lora::init(spi_driver, cs, rst, busy).expect("LoRa radio init");

    // Initialize UART0 for RNode serial protocol (USB-UART bridge on Heltec V3)
    let uart_config = uart::config::Config::default().baudrate(Hertz(115200));
    let uart = UartDriver::new(
        peripherals.uart0,
        peripherals.pins.gpio43, // TX (U0TXD on ESP32-S3)
        peripherals.pins.gpio44, // RX (U0RXD on ESP32-S3)
        Option::<AnyIOPin>::None,
        Option::<AnyIOPin>::None,
        &uart_config,
    )
    .expect("UART0 init");

    // Create event channel (lives for the entire program)
    let (tx, rx) = mpsc::channel();

    let interface_id = InterfaceId(1);
    let mut dio1 = dio1;

    // Spawn button handler thread (always-on, GPIO0 = PRG button)
    let button_pin =
        PinDriver::input(AnyIOPin::from(peripherals.pins.gpio0)).expect("PRG button pin");
    let button_tx = tx.clone();
    let button_stats = display_stats.clone();
    std::thread::Builder::new()
        .name("button".into())
        .stack_size(2048)
        .spawn(move || {
            button::button_loop(button_pin, button_tx, button_stats);
        })
        .expect("failed to spawn button thread");

    // Configure transport engine
    let transport_config = TransportConfig {
        transport_enabled: true,
        identity_hash: Some(identity_hash),
        prefer_shorter_path: false,
        max_paths_per_destination: 2,
        packet_hashlist_max_entries: 1024,
    };

    // Build driver and register interface (once, reused across mode switches)
    let mut driver_inst = driver::Driver::new(transport_config, rx);
    driver_inst.set_stats(display_stats.clone());
    driver_inst.set_identity(identity);
    driver_inst.add_interface(interface_id, writer, None);

    // Initialize BLE NUS (NimBLE host stack + GATT service). Does not start advertising.
    ble::init(&format!("RNS-{}", &identity_hex[..8]));

    log::info!("Reticulum transport node running");

    // Mode controller loop: alternates between standalone, USB bridge, and BLE bridge modes
    loop {
        // Create shutdown flag for this iteration's mode-specific threads
        let shutdown = Arc::new(AtomicBool::new(false));

        // Spawn LoRa reader thread
        let reader_radio = radio.clone();
        let reader_tx = tx.clone();
        let reader_shutdown = shutdown.clone();
        let reader_dio1 = dio1;
        let reader_handle = std::thread::Builder::new()
            .name("lora_rx".into())
            .stack_size(4096)
            .spawn(move || {
                lora::reader_loop(
                    reader_radio,
                    reader_tx,
                    interface_id,
                    reader_shutdown,
                    reader_dio1,
                )
            })
            .expect("failed to spawn LoRa reader thread");

        // Spawn tick thread
        let tick_handle =
            driver::spawn_tick_thread(tx.clone(), config::TICK_INTERVAL_MS, shutdown.clone());

        // Update display mode
        if let Ok(mut s) = display_stats.lock() {
            s.set_mode(display::Mode::Standalone);
        }

        // Run the driver event loop (blocks until bridge detected, shutdown, or disconnect)
        let exit = driver_inst.run(&uart);

        // Signal mode-specific threads to stop
        shutdown.store(true, Ordering::SeqCst);
        dio1 = reader_handle.join().expect("LoRa reader thread panicked");
        let _ = tick_handle.join();

        match exit {
            driver::DriverExit::BridgeRequested => {
                log::info!("Entering RNode USB bridge mode");
                if let Ok(mut s) = display_stats.lock() {
                    s.set_mode(display::Mode::Bridge);
                }

                // Run bridge mode with UART transport (blocks until idle timeout)
                let transport = rnode::UartTransport::new(&uart);
                let bridge = rnode::RNodeBridge::new(
                    radio.clone(),
                    transport,
                    dio1,
                    Some(display_stats.clone()),
                );
                let (bridge_exit, bridge_dio1) = bridge.run();
                dio1 = bridge_dio1;

                // Restore radio to default standalone config
                rnode::restore_default_radio_config(&radio);

                // Drain stale button events accumulated during bridge mode
                driver_inst.drain_events();

                match bridge_exit {
                    rnode::BridgeExit::IdleTimeout => {
                        log::info!("RNode bridge: idle timeout, resuming standalone");
                    }
                    rnode::BridgeExit::Leave => {
                        log::info!("RNode bridge: host sent LEAVE, resuming standalone");
                    }
                }
            }
            driver::DriverExit::BleRequested => {
                log::info!("Entering BLE bridge mode");
                if let Ok(mut s) = display_stats.lock() {
                    s.set_mode(display::Mode::BleWaiting);
                }

                // Start BLE advertising with 30s timeout
                ble::start_advertising(30);

                // Wait up to 30s for a BLE connection
                let deadline = std::time::Instant::now()
                    + std::time::Duration::from_secs(30);
                let connected = loop {
                    if ble::is_connected() {
                        break true;
                    }
                    if std::time::Instant::now() >= deadline {
                        break false;
                    }
                    std::thread::sleep(std::time::Duration::from_millis(100));
                };

                if !connected {
                    ble::stop_advertising();
                    log::info!("BLE: no connection within timeout, resuming standalone");
                    driver_inst.drain_events();
                    continue;
                }

                // Connected — run RNodeBridge with BLE transport
                log::info!("BLE: connected, starting RNode bridge");
                if let Ok(mut s) = display_stats.lock() {
                    s.set_mode(display::Mode::Bridge);
                }

                let transport = rnode::BleTransport::new();
                let bridge = rnode::RNodeBridge::new(
                    radio.clone(),
                    transport,
                    dio1,
                    Some(display_stats.clone()),
                );
                let (bridge_exit, bridge_dio1) = bridge.run();
                dio1 = bridge_dio1;

                // Restore radio to default standalone config
                rnode::restore_default_radio_config(&radio);

                // Disconnect BLE if still connected
                ble::disconnect();

                // Drain stale button events
                driver_inst.drain_events();

                match bridge_exit {
                    rnode::BridgeExit::IdleTimeout => {
                        log::info!("BLE bridge: idle timeout, resuming standalone");
                    }
                    rnode::BridgeExit::Leave => {
                        log::info!("BLE bridge: host sent LEAVE, resuming standalone");
                    }
                }
            }
            driver::DriverExit::Disconnected => {
                log::info!("Driver exited, shutting down");
                break;
            }
        }
    }
}

/// Load identity from NVS, or generate a new one and persist it.
fn load_or_create_identity(nvs_partition: &EspDefaultNvsPartition) -> Identity {
    let nvs =
        EspNvs::<NvsDefault>::new(nvs_partition.clone(), NVS_NAMESPACE, true).expect("NVS open");

    // Try to load existing private key
    let mut key_buf = [0u8; 64];
    if let Ok(Some(_)) = nvs.get_raw(NVS_KEY_IDENTITY, &mut key_buf) {
        log::info!("Loaded identity from NVS");
        return Identity::from_private_key(&key_buf);
    }

    // Generate new identity
    log::info!("Generating new identity");
    let mut rng = rng::EspRng;
    let identity = Identity::new(&mut rng);

    // Persist private key
    if let Some(prv) = identity.get_private_key() {
        let mut nvs_mut = EspNvs::<NvsDefault>::new(nvs_partition.clone(), NVS_NAMESPACE, true)
            .expect("NVS open for write");
        nvs_mut
            .set_raw(NVS_KEY_IDENTITY, &prv)
            .expect("NVS write identity");
        log::info!("Identity saved to NVS");
    }

    identity
}
