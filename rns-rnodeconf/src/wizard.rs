//! The device and model menus of upstream `rnodeconf`'s autoinstall
//! wizard (`-a`), translated from upstream's source by
//! `tools/translate_wizard.py` so the screens read exactly as upstream's.
//! Regenerate the body of `choose_board` with:
//!
//! ```text
//! python3 tools/translate_wizard.py RNS/Utilities/rnodeconf.py 1849 2583
//! ```
//!
//! (line numbers as of upstream 16621a78).

use std::process::exit;

use crate::{graceful_exit, print_donation_block, py_int, rom, wait_for_enter};

/// The board the wizard settled on.
pub struct Board {
    pub product: Option<u8>,
    pub model: Option<u8>,
    pub mcu: Option<u8>,
    pub platform: Option<u8>,
    pub fw_filename: Option<String>,
}

fn read_line() -> String {
    flush();
    let mut line = String::new();
    let _ = std::io::stdin().read_line(&mut line);
    line
}

fn flush() {
    use std::io::Write;
    let _ = std::io::stdout().flush();
}

/// upstream's `clear()`: `os.system('clear')`.
pub fn clear_screen() {
    flush();
    let _ = std::process::Command::new("sh")
        .args(["-c", "clear"])
        .status();
}

/// Ask what kind of device is connected, and which model of it.
#[allow(unused_assignments, clippy::all)]
#[rustfmt::skip]
pub fn choose_board(detected: bool) -> Board {
    let mut selected_product: Option<u8> = None;
    let mut selected_model: Option<u8> = None;
    let mut selected_mcu: Option<u8> = None;
    let mut selected_platform: Option<u8> = None;
    let mut c_mod = false;
    let mut fw_filename: Option<String> = None;

        println!("\n---------------------------------------------------------------------------");
        println!("                               Device Selection");
        if detected {
            println!("\nThe device seems to have an RNode firmware installed, but it was not");
            println!("provisioned correctly, or it is corrupt. We are going to reinstall the");
            println!("correct firmware and provision it.");
        } else {
            println!("\nIt looks like this is a fresh device with no RNode firmware.");
        }
        println!("");
        println!("What kind of device is this?\n");
        println!("       |   Select this option if you have an RNode of a specific");
        println!("      \\ /  type, built from a recipe or bought from a vendor.");
        println!("       '");
        println!("[1]  A specific kind of RNode");
        println!("");
        println!("       |   Select this option if you have put together an RNode");
        println!("      \\ /  of your own design, or if you are prototyping one.");
        println!("       '");
        println!("[2]  Homebrew RNode");
        println!("");
        println!("       |   Select one of these options if you want to easily turn");
        println!("      \\ /  a supported development board into an RNode.");
        println!("       '");
        println!("[3]  LilyGO LoRa32 v2.1 (aka T3 v1.6 / T3 v1.6.1)");
        println!("[4]  LilyGO LoRa32 v2.0");
        println!("[5]  LilyGO LoRa32 v1.0");
        println!("[6]  LilyGO T-Beam");
        println!("[7]  Heltec LoRa32 v2");
        println!("[8]  Heltec LoRa32 v3");
        println!("[9]  Heltec LoRa32 v4");
        println!("[10] LilyGO LoRa T3S3");
        println!("[11] RAK4631");
        println!("[12] LilyGo T-Echo");
        println!("[13] LilyGO T-Beam Supreme");
        println!("[14] LilyGO T-Deck");
        println!("[15] Heltec T114");
        println!("[16] Seeed XIAO ESP32S3 Wio-SX1262");
        println!("");
        println!("---------------------------------------------------------------------------");
        print!("\nEnter the number that matches your device type:\n? ");
        flush();
        selected_product = None;
        let attempt = (|| -> Result<(), ()> {
            let c_dev = py_int(&read_line()).ok_or(())?;
            c_mod = false;
            if c_dev < 1 || c_dev > 16 {
                return Err(());
            } else if c_dev == 1 {
                selected_product = Some(rom::PRODUCT_RNODE);
            } else if c_dev == 2 {
                selected_product = Some(rom::PRODUCT_HMBRW);
                clear_screen();
                println!("");
                println!("---------------------------------------------------------------------------");
                println!("                        Homebrew RNode Installer");
                println!("");
                println!("This option allows you to install and provision the RNode firmware on a");
                println!("custom board design, or a custom device created by coupling a generic");
                println!("development board with a supported transceiver module.");
                println!("");
                println!("Important! Using RNode firmware on homebrew devices should currently be");
                println!("considered experimental. It is not intended for production or critical use.");
                println!("The currently supplied firmware is provided AS-IS as a courtesy to those");
                println!("who would like to experiment with it. Hit enter to continue.");
                println!("---------------------------------------------------------------------------");
                wait_for_enter();
            } else if c_dev == 6 {
                selected_product = Some(rom::PRODUCT_TBEAM);
                clear_screen();
                println!("");
                println!("---------------------------------------------------------------------------");
                println!("                          T-Beam RNode Installer");
                println!("");
                println!("The RNode firmware can currently be installed on T-Beam devices using the");
                println!("SX1276, SX1278, SX1262 and SX1268 transceiver chips.");
                println!("");
                println!("Important! Using RNode firmware on T-Beam devices should currently be");
                println!("considered experimental. It is not intended for production or critical use.");
                println!("The currently supplied firmware is provided AS-IS as a courtesy to those");
                println!("who would like to experiment with it. Hit enter to continue.");
                println!("---------------------------------------------------------------------------");
                wait_for_enter();
            } else if c_dev == 13 {
                selected_product = Some(rom::PRODUCT_TBEAM_S_V1);
                clear_screen();
                println!("");
                println!("---------------------------------------------------------------------------");
                println!("                       T-Beam Supreme RNode Installer");
                println!("");
                println!("The RNode firmware can currently be installed on T-Beam Supreme devices");
                println!("using the SX1262 and SX1268 transceiver chips.");
                println!("");
                println!("Important! Using RNode firmware on T-Beam devices should currently be");
                println!("considered experimental. It is not intended for production or critical use.");
                println!("The currently supplied firmware is provided AS-IS as a courtesy to those");
                println!("who would like to experiment with it. Hit enter to continue.");
                println!("---------------------------------------------------------------------------");
                wait_for_enter();
            } else if c_dev == 14 {
                selected_product = Some(rom::PRODUCT_TDECK);
                clear_screen();
                println!("");
                println!("---------------------------------------------------------------------------");
                println!("                            T-Deck RNode Installer");
                println!("");
                println!("The RNode firmware can currently be installed on T-Deck devices using the");
                println!("SX1262 and SX1268 transceiver chips.");
                println!("");
                println!("Important! Using RNode firmware on T-Beam devices should currently be");
                println!("considered experimental. It is not intended for production or critical use.");
                println!("The currently supplied firmware is provided AS-IS as a courtesy to those");
                println!("who would like to experiment with it. Hit enter to continue.");
                println!("---------------------------------------------------------------------------");
                wait_for_enter();
            } else if c_dev == 4 {
                selected_product = Some(rom::PRODUCT_T32_20);
                clear_screen();
                println!("");
                println!("---------------------------------------------------------------------------");
                println!("                     LilyGO LoRa32 v2.0 RNode Installer");
                println!("");
                println!("Important! Using RNode firmware on LoRa32 devices should currently be");
                println!("considered experimental. It is not intended for production or critical use.");
                println!("The currently supplied firmware is provided AS-IS as a courtesy to those");
                println!("who would like to experiment with it. Hit enter to continue.");
                println!("---------------------------------------------------------------------------");
                wait_for_enter();
            } else if c_dev == 5 {
                selected_product = Some(rom::PRODUCT_T32_10);
                clear_screen();
                println!("");
                println!("---------------------------------------------------------------------------");
                println!("                     LilyGO LoRa32 v1.0 RNode Installer");
                println!("");
                println!("Important! Using RNode firmware on LoRa32 devices should currently be");
                println!("considered experimental. It is not intended for production or critical use.");
                println!("The currently supplied firmware is provided AS-IS as a courtesy to those");
                println!("who would like to experiment with it.");
                println!("");
                println!("Please Note! This device is known to have a faulty battery charging circuit,");
                println!("which can result in overcharging and damaging batteries. If at all possible,");
                println!("it is recommended to avoid this device.");
                println!("");
                println!("Hit enter if you're sure you wish to continue.");
                println!("---------------------------------------------------------------------------");
                wait_for_enter();
            } else if c_dev == 3 {
                selected_product = Some(rom::PRODUCT_T32_21);
                clear_screen();
                println!("");
                println!("---------------------------------------------------------------------------");
                println!("                     LilyGO LoRa32 v2.1 RNode Installer");
                println!("");
                println!("Important! Using RNode firmware on LoRa32 devices should currently be");
                println!("considered experimental. It is not intended for production or critical use.");
                println!("The currently supplied firmware is provided AS-IS as a courtesy to those");
                println!("who would like to experiment with it. Hit enter to continue.");
                println!("---------------------------------------------------------------------------");
                wait_for_enter();
            } else if c_dev == 7 {
                selected_product = Some(rom::PRODUCT_H32_V2);
                clear_screen();
                println!("");
                println!("---------------------------------------------------------------------------");
                println!("                     Heltec LoRa32 v2.0 RNode Installer");
                println!("");
                println!("Important! Using RNode firmware on Heltec devices should currently be");
                println!("considered experimental. It is not intended for production or critical use.");
                println!("");
                println!("The currently supplied firmware is provided AS-IS as a courtesy to those");
                println!("who would like to experiment with it. Hit enter to continue.");
                println!("---------------------------------------------------------------------------");
                wait_for_enter();
            } else if c_dev == 10 {
                selected_product = Some(rom::PRODUCT_RNODE);
                c_mod = true;
                clear_screen();
                println!("");
                println!("---------------------------------------------------------------------------");
                println!("                     LilyGO LoRa32 T3S3 RNode Installer");
                println!("");
                println!("Important! Using RNode firmware on T3S3 devices should currently be");
                println!("considered experimental. It is not intended for production or critical use.");
                println!("");
                println!("The currently supplied firmware is provided AS-IS as a courtesy to those");
                println!("who would like to experiment with it. Hit enter to continue.");
                println!("---------------------------------------------------------------------------");
                wait_for_enter();
            } else if c_dev == 8 {
                selected_product = Some(rom::PRODUCT_H32_V3);
                clear_screen();
                println!("");
                println!("---------------------------------------------------------------------------");
                println!("                     Heltec LoRa32 v3.0 RNode Installer");
                println!("");
                println!("Important! Using RNode firmware on Heltec devices should currently be");
                println!("considered experimental. It is not intended for production or critical use.");
                println!("");
                println!("The currently supplied firmware is provided AS-IS as a courtesy to those");
                println!("who would like to experiment with it. Hit enter to continue.");
                println!("---------------------------------------------------------------------------");
                wait_for_enter();
            } else if c_dev == 9 {
                selected_product = Some(rom::PRODUCT_H32_V4);
                clear_screen();
                println!("");
                println!("---------------------------------------------------------------------------");
                println!("                      Heltec LoRa32 v4 RNode Installer");
                println!("");
                println!("Important! Using RNode firmware on Heltec devices should currently be");
                println!("considered experimental. It is not intended for production or critical use.");
                println!("");
                println!("The currently supplied firmware is provided AS-IS as a courtesy to those");
                println!("who would like to experiment with it. Hit enter to continue.");
                println!("---------------------------------------------------------------------------");
                wait_for_enter();
            } else if c_dev == 11 {
                selected_product = Some(rom::PRODUCT_RAK4631);
                clear_screen();
                println!("");
                println!("---------------------------------------------------------------------------");
                println!("                     RAK4631 RNode Installer");
                println!("");
                println!("Important! Using RNode firmware on RAKwireless devices should currently be");
                println!("considered experimental. It is not intended for production or critical use.");
                println!("The currently supplied firmware is provided AS-IS as a courtesy to those");
                println!("who would like to experiment with it. Hit enter to continue.");
                println!("---------------------------------------------------------------------------");
                wait_for_enter();
            } else if c_dev == 12 {
                selected_product = Some(rom::PRODUCT_TECHO);
                clear_screen();
                println!("");
                println!("---------------------------------------------------------------------------");
                println!("                     LilyGo T-Echo RNode Installer");
                println!("");
                println!("Important! Using RNode firmware on LilyGo T-Echo devices should currently be");
                println!("considered experimental. It is not intended for production or critical use.");
                println!("The currently supplied firmware is provided AS-IS as a courtesy to those");
                println!("who would like to experiment with it. Hit enter to continue.");
                println!("---------------------------------------------------------------------------");
                wait_for_enter();
            } else if c_dev == 15 {
                selected_product = Some(rom::PRODUCT_HELTEC_T114);
                clear_screen();
                println!("");
                println!("---------------------------------------------------------------------------");
                println!("                      Heltec T114 RNode Installer");
                println!("");
                println!("Important! Using RNode firmware on Heltec T114 devices should currently be");
                println!("considered experimental. It is not intended for production or critical use.");
                println!("The currently supplied firmware is provided AS-IS as a courtesy to those");
                println!("who would like to experiment with it. Hit enter to continue.");
                println!("---------------------------------------------------------------------------");
                wait_for_enter();
            } else if c_dev == 16 {
                selected_product = Some(rom::PRODUCT_XIAO_S3);
                clear_screen();
                println!("");
                println!("---------------------------------------------------------------------------");
                println!("                 SeeedStudio XIAO esp32s3 wio RNode Installer");
                println!("");
                println!("Important! Using RNode firmware on SeeedStudio XIAO/wio devices should currently be");
                println!("considered experimental. It is not intended for production or critical use.");
                println!("The currently supplied firmware is provided AS-IS as a courtesy to those");
                println!("who would like to experiment with it. Hit enter to continue.");
                println!("---------------------------------------------------------------------------");
                wait_for_enter();
            }
            Ok(())
        })();
        if attempt.is_err() {
            println!("That device type does not exist, exiting now.");
            graceful_exit(0);
        }
        selected_platform = None;
        selected_model = None;
        selected_mcu = None;
        if selected_product == Some(rom::PRODUCT_HMBRW) {
            println!("\nWhat kind of microcontroller is your board based on?\n");
            println!("[1] AVR ATmega1284P");
            println!("[2] AVR ATmega2560");
            println!("[3] Espressif Systems ESP32");
            print!("\n? ");
            flush();
            let attempt = (|| -> Result<(), ()> {
                let c_mcu = py_int(&read_line()).ok_or(())?;
                if c_mcu < 1 || c_mcu > 3 {
                    return Err(());
                } else if c_mcu == 1 {
                    selected_mcu = Some(rom::MCU_1284P);
                    selected_platform = Some(rom::PLATFORM_AVR);
                } else if c_mcu == 2 {
                    selected_mcu = Some(rom::MCU_2560);
                    selected_platform = Some(rom::PLATFORM_AVR);
                } else if c_mcu == 3 {
                    selected_mcu = Some(rom::MCU_ESP32);
                    selected_platform = Some(rom::PLATFORM_ESP32);
                }
                selected_model = Some(rom::MODEL_FF);
                Ok(())
            })();
            if attempt.is_err() {
                println!("That MCU type does not exist, exiting now.");
                graceful_exit(0);
            }
            println!("\nWhat transceiver module does your board use?\n");
            println!("[1] SX1276/SX1278 with antenna port on PA_BOOST pin");
            println!("[2] SX1276/SX1278 with antenna port on RFO pin");
            print!("\n? ");
            flush();
            let attempt = (|| -> Result<(), ()> {
                let c_trxm = py_int(&read_line()).ok_or(())?;
                if c_trxm < 1 || c_trxm > 3 {
                    return Err(());
                } else if c_trxm == 1 {
                    selected_model = Some(rom::MODEL_FE);
                } else if c_trxm == 2 {
                    selected_model = Some(rom::MODEL_FF);
                }
                Ok(())
            })();
            if attempt.is_err() {
                println!("That transceiver type does not exist, exiting now.");
                graceful_exit(0);
            }
        } else if selected_product == Some(rom::PRODUCT_RNODE) {
            if !c_mod {
                selected_mcu = Some(rom::MCU_1284P);
                println!("\nWhat model is this RNode?\n");
                println!("[1] Handheld v2.1 RNode, 410 - 525 MHz");
                println!("[2] Handheld v2.1 RNode, 820 - 1020 MHz");
                println!("");
                println!("[3] Original v1.x RNode, 410 - 525 MHz");
                println!("[4] Original v1.x RNode, 820 - 1020 MHz");
                println!("");
                println!("[5] Prototype v2.2 RNode, 410 - 525 MHz");
                println!("[6] Prototype v2.2 RNode, 820 - 1020 MHz");
                print!("\n? ");
                flush();
                let attempt = (|| -> Result<(), ()> {
                    let c_model = py_int(&read_line()).ok_or(())?;
                    if c_model < 1 || c_model > 6 {
                        return Err(());
                    } else if c_model == 1 {
                        selected_model = Some(rom::MODEL_A2);
                        selected_mcu = Some(rom::MCU_ESP32);
                        selected_platform = Some(rom::PLATFORM_ESP32);
                    } else if c_model == 2 {
                        selected_model = Some(rom::MODEL_A7);
                        selected_mcu = Some(rom::MCU_ESP32);
                        selected_platform = Some(rom::PLATFORM_ESP32);
                    } else if c_model == 3 {
                        selected_model = Some(rom::MODEL_A4);
                        selected_platform = Some(rom::PLATFORM_AVR);
                    } else if c_model == 4 {
                        selected_model = Some(rom::MODEL_A9);
                        selected_platform = Some(rom::PLATFORM_AVR);
                    } else if c_model == 5 {
                        selected_model = Some(rom::MODEL_A1);
                        selected_mcu = Some(rom::MCU_ESP32);
                        selected_platform = Some(rom::PLATFORM_ESP32);
                    } else if c_model == 6 {
                        selected_model = Some(rom::MODEL_A6);
                        selected_mcu = Some(rom::MCU_ESP32);
                        selected_platform = Some(rom::PLATFORM_ESP32);
                    }
                    Ok(())
                })();
                if attempt.is_err() {
                    println!("That model does not exist, exiting now.");
                    graceful_exit(0);
                }
            } else {
                println!("\nWhat band is this T3S3 for?\n");
                println!("[1] 433 MHz         (with SX1278 chip)");
                println!("[2] 868/915/923 MHz (with SX1276 chip)");
                println!("");
                println!("[3] 433 MHz         (with SX1268 chip)");
                println!("[4] 868/915/923 MHz (with SX1262 chip)");
                println!("");
                println!("[5] 2.4 GHz         (with SX1280 chip and PA)");
                print!("\n? ");
                flush();
                let attempt = (|| -> Result<(), ()> {
                    let c_model = py_int(&read_line()).ok_or(())?;
                    if c_model < 1 || c_model > 5 {
                        return Err(());
                    } else if c_model == 1 {
                        selected_model = Some(rom::MODEL_A5);
                        selected_mcu = Some(rom::MCU_ESP32);
                        selected_platform = Some(rom::PLATFORM_ESP32);
                    } else if c_model == 2 {
                        selected_model = Some(rom::MODEL_AA);
                        selected_mcu = Some(rom::MCU_ESP32);
                        selected_platform = Some(rom::PLATFORM_ESP32);
                    } else if c_model == 3 {
                        selected_model = Some(rom::MODEL_A1);
                        selected_mcu = Some(rom::MCU_ESP32);
                        selected_platform = Some(rom::PLATFORM_ESP32);
                    } else if c_model == 4 {
                        selected_model = Some(rom::MODEL_A6);
                        selected_mcu = Some(rom::MCU_ESP32);
                        selected_platform = Some(rom::PLATFORM_ESP32);
                    } else if c_model == 5 {
                        selected_model = Some(rom::MODEL_AC);
                        selected_mcu = Some(rom::MCU_ESP32);
                        selected_platform = Some(rom::PLATFORM_ESP32);
                    }
                    Ok(())
                })();
                if attempt.is_err() {
                    println!("That model does not exist, exiting now.");
                    graceful_exit(0);
                }
            }
        } else if selected_product == Some(rom::PRODUCT_TBEAM) {
            selected_mcu = Some(rom::MCU_ESP32);
            println!("\nWhat band is this T-Beam for?\n");
            println!("[1] 433 MHz         (with SX1278 chip)");
            println!("[2] 868/915/923 MHz (with SX1276 chip)");
            println!("");
            println!("[3] 433 MHz         (with SX1268 chip)");
            println!("[4] 868/915/923 MHz (with SX1262 chip)");
            print!("\n? ");
            flush();
            let attempt = (|| -> Result<(), ()> {
                let c_model = py_int(&read_line()).ok_or(())?;
                if c_model < 1 || c_model > 4 {
                    return Err(());
                } else if c_model == 1 {
                    selected_model = Some(rom::MODEL_E4);
                    selected_platform = Some(rom::PLATFORM_ESP32);
                } else if c_model == 2 {
                    selected_model = Some(rom::MODEL_E9);
                    selected_platform = Some(rom::PLATFORM_ESP32);
                } else if c_model == 3 {
                    selected_model = Some(rom::MODEL_E3);
                    selected_platform = Some(rom::PLATFORM_ESP32);
                } else if c_model == 4 {
                    selected_model = Some(rom::MODEL_E8);
                    selected_platform = Some(rom::PLATFORM_ESP32);
                }
                Ok(())
            })();
            if attempt.is_err() {
                println!("That band does not exist, exiting now.");
                graceful_exit(0);
            }
        } else if selected_product == Some(rom::PRODUCT_TBEAM_S_V1) {
            selected_mcu = Some(rom::MCU_ESP32);
            println!("\nWhat band is this T-Beam Supreme for?\n");
            println!("[1] 433 MHz         (with SX1268 chip)");
            println!("[2] 868/915/923 MHz (with SX1262 chip)");
            print!("\n? ");
            flush();
            let attempt = (|| -> Result<(), ()> {
                let c_model = py_int(&read_line()).ok_or(())?;
                if c_model < 1 || c_model > 2 {
                    return Err(());
                } else if c_model == 1 {
                    selected_model = Some(rom::MODEL_DB);
                    selected_platform = Some(rom::PLATFORM_ESP32);
                } else if c_model == 2 {
                    selected_model = Some(rom::MODEL_DC);
                    selected_platform = Some(rom::PLATFORM_ESP32);
                }
                Ok(())
            })();
            if attempt.is_err() {
                println!("That band does not exist, exiting now.");
                graceful_exit(0);
            }
        } else if selected_product == Some(rom::PRODUCT_TDECK) {
            selected_mcu = Some(rom::MCU_ESP32);
            println!("\nWhat band is this T-Deck for?\n");
            println!("[1] 433 MHz         (with SX1268 chip)");
            println!("[2] 868/915/923 MHz (with SX1262 chip)");
            print!("\n? ");
            flush();
            let attempt = (|| -> Result<(), ()> {
                let c_model = py_int(&read_line()).ok_or(())?;
                if c_model < 1 || c_model > 2 {
                    return Err(());
                } else if c_model == 1 {
                    selected_model = Some(rom::MODEL_D4);
                    selected_platform = Some(rom::PLATFORM_ESP32);
                } else if c_model == 2 {
                    selected_model = Some(rom::MODEL_D9);
                    selected_platform = Some(rom::PLATFORM_ESP32);
                }
                Ok(())
            })();
            if attempt.is_err() {
                println!("That band does not exist, exiting now.");
                graceful_exit(0);
            }
        } else if selected_product == Some(rom::PRODUCT_T32_10) {
            selected_mcu = Some(rom::MCU_ESP32);
            println!("\nWhat band is this LoRa32 for?\n");
            println!("[1] 433 MHz");
            println!("[2] 868 MHz");
            println!("[3] 915 MHz");
            println!("[4] 923 MHz");
            print!("\n? ");
            flush();
            let attempt = (|| -> Result<(), ()> {
                let c_model = py_int(&read_line()).ok_or(())?;
                if c_model < 1 || c_model > 4 {
                    return Err(());
                } else if c_model == 1 {
                    selected_model = Some(rom::MODEL_BA);
                    selected_platform = Some(rom::PLATFORM_ESP32);
                } else if c_model > 1 {
                    selected_model = Some(rom::MODEL_BB);
                    selected_platform = Some(rom::PLATFORM_ESP32);
                }
                Ok(())
            })();
            if attempt.is_err() {
                println!("That band does not exist, exiting now.");
                graceful_exit(0);
            }
        } else if selected_product == Some(rom::PRODUCT_T32_20) {
            selected_mcu = Some(rom::MCU_ESP32);
            println!("\nWhat band is this LoRa32 for?\n");
            println!("[1] 433 MHz");
            println!("[2] 868 MHz");
            println!("[3] 915 MHz");
            println!("[4] 923 MHz");
            print!("\n? ");
            flush();
            let attempt = (|| -> Result<(), ()> {
                let c_model = py_int(&read_line()).ok_or(())?;
                if c_model < 1 || c_model > 4 {
                    return Err(());
                } else if c_model == 1 {
                    selected_model = Some(rom::MODEL_B3);
                    selected_platform = Some(rom::PLATFORM_ESP32);
                } else if c_model > 1 {
                    selected_model = Some(rom::MODEL_B8);
                    selected_platform = Some(rom::PLATFORM_ESP32);
                }
                Ok(())
            })();
            if attempt.is_err() {
                println!("That band does not exist, exiting now.");
                graceful_exit(0);
            }
        } else if selected_product == Some(rom::PRODUCT_T32_21) {
            selected_mcu = Some(rom::MCU_ESP32);
            println!("\nWhat band is this LoRa32 for?\n");
            println!("[1] 433 MHz");
            println!("[2] 868/915/923 MHz");
            println!("[3] 433 MHz, with TCXO");
            println!("[4] 868/915/923 MHz, with TCXO");
            print!("\n? ");
            flush();
            let attempt = (|| -> Result<(), ()> {
                let c_model = py_int(&read_line()).ok_or(())?;
                if c_model < 1 || c_model > 4 {
                    return Err(());
                } else if c_model == 1 {
                    selected_model = Some(rom::MODEL_B4);
                    selected_platform = Some(rom::PLATFORM_ESP32);
                } else if c_model == 2 {
                    selected_model = Some(rom::MODEL_B9);
                    selected_platform = Some(rom::PLATFORM_ESP32);
                } else if c_model == 3 {
                    selected_model = Some(rom::MODEL_B4_TCXO);
                    selected_platform = Some(rom::PLATFORM_ESP32);
                } else if c_model == 4 {
                    selected_model = Some(rom::MODEL_B9_TCXO);
                    selected_platform = Some(rom::PLATFORM_ESP32);
                }
                Ok(())
            })();
            if attempt.is_err() {
                println!("That band does not exist, exiting now.");
                graceful_exit(0);
            }
        } else if selected_product == Some(rom::PRODUCT_H32_V2) {
            selected_mcu = Some(rom::MCU_ESP32);
            println!("\nWhat band is this Heltec LoRa32 V2 for?\n");
            println!("[1] 433 MHz");
            println!("[2] 868 MHz");
            println!("[3] 915 MHz");
            println!("[4] 923 MHz");
            print!("\n? ");
            flush();
            let attempt = (|| -> Result<(), ()> {
                let c_model = py_int(&read_line()).ok_or(())?;
                if c_model < 1 || c_model > 4 {
                    return Err(());
                } else if c_model == 1 {
                    selected_model = Some(rom::MODEL_C4);
                    selected_platform = Some(rom::PLATFORM_ESP32);
                } else if c_model > 1 {
                    selected_model = Some(rom::MODEL_C9);
                    selected_platform = Some(rom::PLATFORM_ESP32);
                }
                Ok(())
            })();
            if attempt.is_err() {
                println!("That band does not exist, exiting now.");
                graceful_exit(0);
            }
        } else if selected_product == Some(rom::PRODUCT_H32_V3) {
            selected_mcu = Some(rom::MCU_ESP32);
            println!("\nWhat band is this Heltec LoRa32 V3 for?\n");
            println!("[1] 433 MHz");
            println!("[2] 868 MHz");
            println!("[3] 915 MHz");
            println!("[4] 923 MHz");
            print!("\n? ");
            flush();
            let attempt = (|| -> Result<(), ()> {
                let c_model = py_int(&read_line()).ok_or(())?;
                if c_model < 1 || c_model > 4 {
                    return Err(());
                } else if c_model == 1 {
                    selected_model = Some(rom::MODEL_C5);
                    selected_platform = Some(rom::PLATFORM_ESP32);
                } else if c_model > 1 {
                    selected_model = Some(rom::MODEL_CA);
                    selected_platform = Some(rom::PLATFORM_ESP32);
                }
                Ok(())
            })();
            if attempt.is_err() {
                println!("That band does not exist, exiting now.");
                exit(0);
            }
        } else if selected_product == Some(rom::PRODUCT_H32_V4) {
            selected_mcu = Some(rom::MCU_ESP32);
            println!("\nWhat band is this Heltec LoRa32 V4 for?\n");
            println!("[1] 868 MHz (28 dBm output)");
            println!("[2] 915 MHz (28 dBm output)");
            println!("[3] 923 MHz (28 dBm output)");
            print!("\n? ");
            flush();
            let attempt = (|| -> Result<(), ()> {
                let c_model = py_int(&read_line()).ok_or(())?;
                if c_model < 1 || c_model > 3 {
                    return Err(());
                } else {
                    selected_model = Some(rom::MODEL_C8);
                    selected_platform = Some(rom::PLATFORM_ESP32);
                }
                Ok(())
            })();
            if attempt.is_err() {
                println!("That band does not exist, exiting now.");
                exit(0);
            }
        } else if selected_product == Some(rom::PRODUCT_HELTEC_T114) {
            selected_mcu = Some(rom::MCU_NRF52);
            println!("\nWhat band is this Heltec T114 for?\n");
            println!("[1] 433 MHz");
            println!("[2] 868 MHz");
            println!("[3] 915 MHz");
            println!("[4] 923 MHz");
            print!("\n? ");
            flush();
            let attempt = (|| -> Result<(), ()> {
                let c_model = py_int(&read_line()).ok_or(())?;
                if c_model < 1 || c_model > 4 {
                    return Err(());
                } else if c_model == 1 {
                    selected_model = Some(rom::MODEL_C6);
                    selected_platform = Some(rom::PLATFORM_NRF52);
                } else if c_model > 1 {
                    selected_model = Some(rom::MODEL_C7);
                    selected_platform = Some(rom::PLATFORM_NRF52);
                }
                Ok(())
            })();
            if attempt.is_err() {
                println!("That band does not exist, exiting now.");
                exit(0);
            }
        } else if selected_product == Some(rom::PRODUCT_XIAO_S3) {
            selected_mcu = Some(rom::MCU_ESP32);
            println!("\nWhat band is this XIAO esp32s3 wio module for?\n");
            println!("[1] 433 MHz");
            println!("[2] 868 MHz");
            print!("\n? ");
            flush();
            let attempt = (|| -> Result<(), ()> {
                let c_model = py_int(&read_line()).ok_or(())?;
                if c_model < 1 || c_model > 2 {
                    return Err(());
                } else if c_model == 1 {
                    selected_model = Some(rom::MODEL_DE);
                    selected_platform = Some(rom::PLATFORM_ESP32);
                } else if c_model == 2 {
                    selected_model = Some(rom::MODEL_DD);
                    selected_platform = Some(rom::PLATFORM_ESP32);
                }
                Ok(())
            })();
            if attempt.is_err() {
                println!("That band does not exist, exiting now.");
                exit(0);
            }
        } else if selected_product == Some(rom::PRODUCT_RAK4631) {
            selected_mcu = Some(rom::MCU_NRF52);
            println!("\nWhat band is this RAK4631 for?\n");
            println!("[1] 433 MHz");
            println!("[2] 868 MHz");
            println!("[3] 915 MHz");
            println!("[4] 923 MHz");
            print!("\n? ");
            flush();
            let attempt = (|| -> Result<(), ()> {
                let c_model = py_int(&read_line()).ok_or(())?;
                if c_model < 1 || c_model > 4 {
                    return Err(());
                } else if c_model == 1 {
                    selected_model = Some(rom::MODEL_11);
                    selected_platform = Some(rom::PLATFORM_NRF52);
                } else if c_model > 1 {
                    selected_model = Some(rom::MODEL_12);
                    selected_platform = Some(rom::PLATFORM_NRF52);
                }
                Ok(())
            })();
            if attempt.is_err() {
                println!("That band does not exist, exiting now.");
                graceful_exit(0);
            }
        } else if selected_product == Some(rom::PRODUCT_TECHO) {
            selected_mcu = Some(rom::MCU_NRF52);
            println!("\nWhat band is this T-Echo for?\n");
            println!("[1] 433 MHz");
            println!("[2] 868 MHz");
            println!("[3] 915 MHz");
            println!("[4] 923 MHz");
            print!("\n? ");
            flush();
            let attempt = (|| -> Result<(), ()> {
                let c_model = py_int(&read_line()).ok_or(())?;
                if c_model < 1 || c_model > 4 {
                    return Err(());
                } else if c_model == 1 {
                    selected_model = Some(rom::MODEL_16);
                    selected_platform = Some(rom::PLATFORM_NRF52);
                } else if c_model > 1 {
                    selected_model = Some(rom::MODEL_17);
                    selected_platform = Some(rom::PLATFORM_NRF52);
                }
                Ok(())
            })();
            if attempt.is_err() {
                println!("That band does not exist, exiting now.");
                graceful_exit(0);
            }
        }
        if selected_model != Some(rom::MODEL_FF) && selected_model != Some(rom::MODEL_FE) {
            fw_filename = selected_model.and_then(rom::model).and_then(|m| m.firmware).map(str::to_string);
        } else if selected_platform == Some(rom::PLATFORM_AVR) {
            if selected_mcu == Some(rom::MCU_1284P) {
                fw_filename = Some("rnode_firmware.hex".to_string());
            } else if selected_mcu == Some(rom::MCU_2560) {
                fw_filename = Some("rnode_firmware_m2560.hex".to_string());
            }
        } else if selected_platform == Some(rom::PLATFORM_ESP32) {
            fw_filename = None;
            println!("\nWhat kind of ESP32 board is this?\n");
            println!("[1] Adafruit Feather ESP32 (HUZZAH32)");
            println!("[2] Generic ESP32 board");
            print!("\n? ");
            flush();
            let attempt = (|| -> Result<(), ()> {
                let c_eboard = py_int(&read_line()).ok_or(())?;
                if c_eboard < 1 || c_eboard > 2 {
                    return Err(());
                } else if c_eboard == 1 {
                    fw_filename = Some("rnode_firmware_featheresp32.zip".to_string());
                } else if c_eboard == 2 {
                    fw_filename = Some("rnode_firmware_esp32_generic.zip".to_string());
                }
                Ok(())
            })();
            if attempt.is_err() {
                println!("That ESP32 board does not exist, exiting now.");
                graceful_exit(0);
            }
        }
        if fw_filename.is_none() {
            println!("");
            println!("Sorry, no firmware for your board currently exists.");
            println!("Help making it a reality by contributing code or by");
            println!("donating to the project.");
            println!("");
            print_donation_block();
            println!("");
            graceful_exit(0);
        }

    Board {
        product: selected_product,
        model: selected_model,
        mcu: selected_mcu,
        platform: selected_platform,
        fw_filename,
    }
}

/// The autoinstall wizard up to flashing: pick the port and the board,
/// confirm, and fetch the firmware. Returns the port, the board and the
/// firmware package; flashing, key generation and bootstrapping follow
/// in the main flow, as upstream's wizard hands them on.
pub fn run(
    port: Option<&str>,
    use_extracted: bool,
    firmware: &mut crate::firmware::Firmware,
) -> (String, Board, String) {
    use crate::{log, ports};
    clear_screen();
    if port.is_none() {
        println!("\nHello!\n\nThis guide will help you install the RNode firmware on supported");
        println!("and homebrew devices. Please connect the device you wish to set\nup now. Hit enter when it is connected.");
        wait_for_enter();
    }
    let port = match port {
        None => {
            let port = crate::select_port();
            clear_screen();
            println!(
                "\nOk, using device on {} ({}, {})",
                port.device,
                ports::py_str(&port.product),
                ports::py_str(&port.serial_number)
            );
            port.device
        }
        // Upstream only accepts a port it lists; a port it does not, such
        // as a pseudo-terminal, is used as given here.
        Some(port) => {
            println!("\nUsing device on {port}");
            port.to_string()
        }
    };
    println!("\nProbing device...");
    let (reader, writer) = match crate::open_serial(&port) {
        Ok(handles) => handles,
        Err(e) => {
            log("Could not open the specified serial port. The contained exception was:");
            log(&format!(
                "[Errno {}] could not open port {port}: {e}",
                e.raw_os_error().unwrap_or(0)
            ));
            graceful_exit(0);
        }
    };
    let mut rnode = crate::RNode::new(reader, writer);
    if rnode.device_probe().is_err() {
        log("No answer from device");
    } else {
        let reported = rnode.reported();
        log("Device connected");
        log(&format!(
            "Current firmware version: {}",
            reported.version().unwrap_or_else(|| "None".into())
        ));
    }
    let detected = rnode.reported().detected == Some(true);
    if detected {
        log("Trying to read EEPROM...");
        let (_, info) = crate::read_eeprom(&mut rnode, &port);
        if info.provisioned && info.signature_valid {
            println!("\nThis device is already installed and provisioned. No further action will");
            println!("be taken. If you wish to completely reinstall this device, you must first");
            println!("wipe the current EEPROM. See the help for more info.\n\nExiting now.");
            graceful_exit(0);
        }
    }

    let mut board = choose_board(detected);
    if use_extracted {
        board.fw_filename = Some(crate::firmware::EXTRACTED.to_string());
    }
    let fw_filename = board.fw_filename.clone().unwrap_or_default();
    let name = |name: Option<&str>| name.unwrap_or("None").to_string();
    clear_screen();
    println!();
    println!("------------------------------------------------------------------------------");
    println!("                               Installer Ready");
    println!();
    println!("Ok, that should be all the information we need. Please confirm the following");
    println!("summary before proceeding. In the next step, the device will be flashed and");
    println!("provisioned, so make sure that you are satisfied with your choices.\n");
    println!("Serial port     : {port}");
    println!(
        "Device type     : {} {}",
        name(board.product.and_then(rom::product_name)),
        name(board.model.and_then(rom::model).map(|m| m.band))
    );
    println!(
        "Platform        : {}",
        name(board.platform.and_then(rom::platform_name))
    );
    println!(
        "Device MCU      : {}",
        name(board.mcu.and_then(rom::mcu_name))
    );
    println!("Firmware file   : {fw_filename}");
    println!();
    println!("------------------------------------------------------------------------------");
    print!("\nIs the above correct? [y/N] ");
    if read_line().trim_end_matches(['\r', '\n']).to_lowercase() != "y" {
        println!("OK, aborting now.");
        graceful_exit(0);
    }

    log("Checking firmware file availability...");
    firmware.ensure(&fw_filename);
    let _ = rnode.disconnect();
    (port, board, fw_filename)
}

/// What upstream prints once an autoinstall has bootstrapped the device.
pub fn print_completion() {
    println!();
    println!("RNode Firmware autoinstallation complete!");
    println!();
    println!("To use your device with Reticulum, read the documetation at:");
    println!();
    println!("https://markqvist.github.io/Reticulum/manual/gettingstartedfast.html");
    println!();
    println!("* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *");
    println!("                              Important!            ");
    println!();
    println!("ESP32-based RNodes are created with the RNode Bootstrap Console on-board.");
    println!();
    println!("This repository is hosted directly on the RNode, and contains a wealth of");
    println!("information, software and tools.");
    println!();
    println!("The RNode Bootstrap Console also contains everything needed to build");
    println!("and replicate RNodes, including detailed build recipes, 3D-printable");
    println!("cases, and copies of the source code for both the RNode Firmware,");
    println!("Reticulum and other utilities.");
    println!();
    println!("To activate the RNode Bootstrap Console, power up your RNode and hold");
    println!("down the user button for 10+ seconds, then release. The RNode will now");
    println!("reboot into console mode, and activate a WiFi access point for you to");
    println!("connect to. The console is then reachable at: http://10.0.0.1");
    println!();
    println!("* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *");
    println!();
    println!("Thank you for using this utility! Please help the project by");
    println!("contributing code and reporting bugs, or by donating!");
    println!();
    println!("Your contributions and donations directly further the realisation");
    println!("of truly open, free and resilient communications systems.");
    println!();
    print_donation_block();
    println!();
}
