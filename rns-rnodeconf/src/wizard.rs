//! The device and model menus of upstream `rnodeconf`'s autoinstall
//! wizard (`-a`). The menus' screens and the boards each answer selects
//! are kept as tables transcribed from upstream's source, so the screens
//! read exactly as upstream's.

use crate::{graceful_exit, print_donation_block, py_int, rom, wait_for_enter};

/// The board the wizard settled on.
pub(crate) struct Board {
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
pub(crate) fn clear_screen() {
    flush();
    let _ = std::process::Command::new("sh")
        .args(["-c", "clear"])
        .status();
}

/// Ask what kind of device is connected, and which model of it.
pub(crate) fn choose_board(detected: bool) -> Board {
    let (selected_product, c_mod) = choose_product(detected);
    choose_model(selected_product, c_mod)
}

/// The first question: what kind of device this is, and upstream's
/// `c_mod`: whether it is the LilyGO LoRa T3S3, an RNode product whose
/// models are asked from their own list.
fn choose_product(detected: bool) -> (Option<u8>, bool) {
    println!("\n---------------------------------------------------------------------------");
    println!("                               Device Selection");
    if detected {
        println!("\nThe device seems to have an RNode firmware installed, but it was not");
        println!("provisioned correctly, or it is corrupt. We are going to reinstall the");
        println!("correct firmware and provision it.");
    } else {
        println!("\nIt looks like this is a fresh device with no RNode firmware.");
    }
    println!();
    println!("What kind of device is this?\n");
    println!("       |   Select this option if you have an RNode of a specific");
    println!("      \\ /  type, built from a recipe or bought from a vendor.");
    println!("       '");
    println!("[1]  A specific kind of RNode");
    println!();
    println!("       |   Select this option if you have put together an RNode");
    println!("      \\ /  of your own design, or if you are prototyping one.");
    println!("       '");
    println!("[2]  Homebrew RNode");
    println!();
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
    println!();
    println!("---------------------------------------------------------------------------");
    print!("\nEnter the number that matches your device type:\n? ");
    let Some(device) = read_choice(&DEVICES) else {
        println!("That device type does not exist, exiting now.");
        graceful_exit(0);
    };
    if let Some(notice) = &device.notice {
        notice.show();
    }
    (Some(device.product), device.t3s3)
}

/// Reads a menu answer: the 1-based number of one of `choices`.
fn read_choice<T>(choices: &[T]) -> Option<&T> {
    flush();
    let answer = py_int(&read_line())?;
    let index = usize::try_from(answer).ok()?.checked_sub(1)?;
    choices.get(index)
}

/// An entry of the device menu.
struct Device {
    product: u8,
    /// upstream's `c_mod`: the LilyGO LoRa T3S3, an RNode product with its
    /// own model list.
    t3s3: bool,
    /// What upstream shows once the entry is picked.
    notice: Option<Notice>,
}

/// A screen upstream shows about a device before going on.
struct Notice {
    title: &'static str,
    body: &'static [&'static str],
}

impl Notice {
    fn show(&self) {
        clear_screen();
        println!();
        println!("---------------------------------------------------------------------------");
        println!("{}", self.title);
        println!();
        for line in self.body {
            println!("{line}");
        }
        println!("---------------------------------------------------------------------------");
        wait_for_enter();
    }
}

/// The device menu's entries, in menu order.
const DEVICES: [Device; 16] = [
    Device {
        product: rom::PRODUCT_RNODE,
        t3s3: false,
        notice: None,
    },
    Device {
        product: rom::PRODUCT_HMBRW,
        t3s3: false,
        notice: Some(Notice {
            title: "                        Homebrew RNode Installer",
            body: &[
                "This option allows you to install and provision the RNode firmware on a",
                "custom board design, or a custom device created by coupling a generic",
                "development board with a supported transceiver module.",
                "",
                "Important! Using RNode firmware on homebrew devices should currently be",
                "considered experimental. It is not intended for production or critical use.",
                "The currently supplied firmware is provided AS-IS as a courtesy to those",
                "who would like to experiment with it. Hit enter to continue.",
            ],
        }),
    },
    Device {
        product: rom::PRODUCT_T32_21,
        t3s3: false,
        notice: Some(Notice {
            title: "                     LilyGO LoRa32 v2.1 RNode Installer",
            body: &[
                "Important! Using RNode firmware on LoRa32 devices should currently be",
                "considered experimental. It is not intended for production or critical use.",
                "The currently supplied firmware is provided AS-IS as a courtesy to those",
                "who would like to experiment with it. Hit enter to continue.",
            ],
        }),
    },
    Device {
        product: rom::PRODUCT_T32_20,
        t3s3: false,
        notice: Some(Notice {
            title: "                     LilyGO LoRa32 v2.0 RNode Installer",
            body: &[
                "Important! Using RNode firmware on LoRa32 devices should currently be",
                "considered experimental. It is not intended for production or critical use.",
                "The currently supplied firmware is provided AS-IS as a courtesy to those",
                "who would like to experiment with it. Hit enter to continue.",
            ],
        }),
    },
    Device {
        product: rom::PRODUCT_T32_10,
        t3s3: false,
        notice: Some(Notice {
            title: "                     LilyGO LoRa32 v1.0 RNode Installer",
            body: &[
                "Important! Using RNode firmware on LoRa32 devices should currently be",
                "considered experimental. It is not intended for production or critical use.",
                "The currently supplied firmware is provided AS-IS as a courtesy to those",
                "who would like to experiment with it.",
                "",
                "Please Note! This device is known to have a faulty battery charging circuit,",
                "which can result in overcharging and damaging batteries. If at all possible,",
                "it is recommended to avoid this device.",
                "",
                "Hit enter if you're sure you wish to continue.",
            ],
        }),
    },
    Device {
        product: rom::PRODUCT_TBEAM,
        t3s3: false,
        notice: Some(Notice {
            title: "                          T-Beam RNode Installer",
            body: &[
                "The RNode firmware can currently be installed on T-Beam devices using the",
                "SX1276, SX1278, SX1262 and SX1268 transceiver chips.",
                "",
                "Important! Using RNode firmware on T-Beam devices should currently be",
                "considered experimental. It is not intended for production or critical use.",
                "The currently supplied firmware is provided AS-IS as a courtesy to those",
                "who would like to experiment with it. Hit enter to continue.",
            ],
        }),
    },
    Device {
        product: rom::PRODUCT_H32_V2,
        t3s3: false,
        notice: Some(Notice {
            title: "                     Heltec LoRa32 v2.0 RNode Installer",
            body: &[
                "Important! Using RNode firmware on Heltec devices should currently be",
                "considered experimental. It is not intended for production or critical use.",
                "",
                "The currently supplied firmware is provided AS-IS as a courtesy to those",
                "who would like to experiment with it. Hit enter to continue.",
            ],
        }),
    },
    Device {
        product: rom::PRODUCT_H32_V3,
        t3s3: false,
        notice: Some(Notice {
            title: "                     Heltec LoRa32 v3.0 RNode Installer",
            body: &[
                "Important! Using RNode firmware on Heltec devices should currently be",
                "considered experimental. It is not intended for production or critical use.",
                "",
                "The currently supplied firmware is provided AS-IS as a courtesy to those",
                "who would like to experiment with it. Hit enter to continue.",
            ],
        }),
    },
    Device {
        product: rom::PRODUCT_H32_V4,
        t3s3: false,
        notice: Some(Notice {
            title: "                      Heltec LoRa32 v4 RNode Installer",
            body: &[
                "Important! Using RNode firmware on Heltec devices should currently be",
                "considered experimental. It is not intended for production or critical use.",
                "",
                "The currently supplied firmware is provided AS-IS as a courtesy to those",
                "who would like to experiment with it. Hit enter to continue.",
            ],
        }),
    },
    Device {
        product: rom::PRODUCT_RNODE,
        t3s3: true,
        notice: Some(Notice {
            title: "                     LilyGO LoRa32 T3S3 RNode Installer",
            body: &[
                "Important! Using RNode firmware on T3S3 devices should currently be",
                "considered experimental. It is not intended for production or critical use.",
                "",
                "The currently supplied firmware is provided AS-IS as a courtesy to those",
                "who would like to experiment with it. Hit enter to continue.",
            ],
        }),
    },
    Device {
        product: rom::PRODUCT_RAK4631,
        t3s3: false,
        notice: Some(Notice {
            title: "                     RAK4631 RNode Installer",
            body: &[
                "Important! Using RNode firmware on RAKwireless devices should currently be",
                "considered experimental. It is not intended for production or critical use.",
                "The currently supplied firmware is provided AS-IS as a courtesy to those",
                "who would like to experiment with it. Hit enter to continue.",
            ],
        }),
    },
    Device {
        product: rom::PRODUCT_TECHO,
        t3s3: false,
        notice: Some(Notice {
            title: "                     LilyGo T-Echo RNode Installer",
            body: &[
                "Important! Using RNode firmware on LilyGo T-Echo devices should currently be",
                "considered experimental. It is not intended for production or critical use.",
                "The currently supplied firmware is provided AS-IS as a courtesy to those",
                "who would like to experiment with it. Hit enter to continue.",
            ],
        }),
    },
    Device {
        product: rom::PRODUCT_TBEAM_S_V1,
        t3s3: false,
        notice: Some(Notice {
            title: "                       T-Beam Supreme RNode Installer",
            body: &[
                "The RNode firmware can currently be installed on T-Beam Supreme devices",
                "using the SX1262 and SX1268 transceiver chips.",
                "",
                "Important! Using RNode firmware on T-Beam devices should currently be",
                "considered experimental. It is not intended for production or critical use.",
                "The currently supplied firmware is provided AS-IS as a courtesy to those",
                "who would like to experiment with it. Hit enter to continue.",
            ],
        }),
    },
    Device {
        product: rom::PRODUCT_TDECK,
        t3s3: false,
        notice: Some(Notice {
            title: "                            T-Deck RNode Installer",
            body: &[
                "The RNode firmware can currently be installed on T-Deck devices using the",
                "SX1262 and SX1268 transceiver chips.",
                "",
                "Important! Using RNode firmware on T-Beam devices should currently be",
                "considered experimental. It is not intended for production or critical use.",
                "The currently supplied firmware is provided AS-IS as a courtesy to those",
                "who would like to experiment with it. Hit enter to continue.",
            ],
        }),
    },
    Device {
        product: rom::PRODUCT_HELTEC_T114,
        t3s3: false,
        notice: Some(Notice {
            title: "                      Heltec T114 RNode Installer",
            body: &[
                "Important! Using RNode firmware on Heltec T114 devices should currently be",
                "considered experimental. It is not intended for production or critical use.",
                "The currently supplied firmware is provided AS-IS as a courtesy to those",
                "who would like to experiment with it. Hit enter to continue.",
            ],
        }),
    },
    Device {
        product: rom::PRODUCT_XIAO_S3,
        t3s3: false,
        notice: Some(Notice {
            title: "                 SeeedStudio XIAO esp32s3 wio RNode Installer",
            body: &[
                "Important! Using RNode firmware on SeeedStudio XIAO/wio devices should currently be",
                "considered experimental. It is not intended for production or critical use.",
                "The currently supplied firmware is provided AS-IS as a courtesy to those",
                "who would like to experiment with it. Hit enter to continue.",
            ],
        }),
    },
];

/// A numbered question of the wizard, and what each answer selects.
struct Menu<T: 'static> {
    /// Printed before the options.
    question: &'static str,
    /// The option lines, blank separators included.
    options: &'static [&'static str],
    /// What each accepted answer selects, in answer order. upstream accepts
    /// more answers than it lists in places.
    picks: &'static [T],
    /// Printed, before exiting, for an answer that is no option.
    invalid: &'static str,
}

impl<T> Menu<T> {
    fn ask(&self) -> &'static T {
        println!("{}", self.question);
        for line in self.options {
            println!("{line}");
        }
        print!("\n? ");
        let Some(pick) = read_choice(self.picks) else {
            println!("{}", self.invalid);
            graceful_exit(0);
        };
        pick
    }
}

/// What a model menu answer selects; `None` leaves a field as it was.
#[derive(Clone, Copy)]
struct Pick {
    model: Option<u8>,
    mcu: Option<u8>,
    platform: Option<u8>,
}

impl Pick {
    /// A model on `platform`.
    const fn on(model: u8, platform: u8) -> Self {
        Self {
            model: Some(model),
            mcu: None,
            platform: Some(platform),
        }
    }

    /// A model with `mcu` on `platform`.
    const fn with_mcu(model: u8, mcu: u8, platform: u8) -> Self {
        Self {
            model: Some(model),
            mcu: Some(mcu),
            platform: Some(platform),
        }
    }

    /// Only a model.
    const fn model(model: u8) -> Self {
        Self {
            model: Some(model),
            mcu: None,
            platform: None,
        }
    }

    /// Nothing.
    const NONE: Self = Self {
        model: None,
        mcu: None,
        platform: None,
    };

    fn apply(self, board: &mut Board) {
        board.model = self.model.or(board.model);
        board.mcu = self.mcu.or(board.mcu);
        board.platform = self.platform.or(board.platform);
    }
}

/// The model questions for a device menu entry.
struct ModelQuestions {
    product: u8,
    t3s3: bool,
    /// The MCU known before asking.
    mcu: Option<u8>,
    menus: &'static [Menu<Pick>],
}

const BAD_MODEL: &str = "That model does not exist, exiting now.";
const BAD_BAND: &str = "That band does not exist, exiting now.";

const ESP32: u8 = rom::PLATFORM_ESP32;
const NRF52: u8 = rom::PLATFORM_NRF52;

/// Four bands, the first on `low` and the rest on `high`.
const fn split_band(low: u8, high: u8, platform: u8) -> [Pick; 4] {
    [
        Pick::on(low, platform),
        Pick::on(high, platform),
        Pick::on(high, platform),
        Pick::on(high, platform),
    ]
}

const BANDS_433_868_915_923: &[&str] =
    &["[1] 433 MHz", "[2] 868 MHz", "[3] 915 MHz", "[4] 923 MHz"];
const BANDS_SX126X: &[&str] = &[
    "[1] 433 MHz         (with SX1268 chip)",
    "[2] 868/915/923 MHz (with SX1262 chip)",
];

/// upstream's model questions, per device menu entry.
const MODEL_QUESTIONS: &[ModelQuestions] = &[
    ModelQuestions {
        product: rom::PRODUCT_HMBRW,
        t3s3: false,
        mcu: None,
        menus: &[
            Menu {
                question: "\nWhat kind of microcontroller is your board based on?\n",
                options: &[
                    "[1] AVR ATmega1284P",
                    "[2] AVR ATmega2560",
                    "[3] Espressif Systems ESP32",
                ],
                picks: &[
                    Pick::with_mcu(rom::MODEL_FF, rom::MCU_1284P, rom::PLATFORM_AVR),
                    Pick::with_mcu(rom::MODEL_FF, rom::MCU_2560, rom::PLATFORM_AVR),
                    Pick::with_mcu(rom::MODEL_FF, rom::MCU_ESP32, ESP32),
                ],
                invalid: "That MCU type does not exist, exiting now.",
            },
            Menu {
                question: "\nWhat transceiver module does your board use?\n",
                options: &[
                    "[1] SX1276/SX1278 with antenna port on PA_BOOST pin",
                    "[2] SX1276/SX1278 with antenna port on RFO pin",
                ],
                picks: &[
                    Pick::model(rom::MODEL_FE),
                    Pick::model(rom::MODEL_FF),
                    Pick::NONE,
                ],
                invalid: "That transceiver type does not exist, exiting now.",
            },
        ],
    },
    ModelQuestions {
        product: rom::PRODUCT_RNODE,
        t3s3: false,
        mcu: Some(rom::MCU_1284P),
        menus: &[Menu {
            question: "\nWhat model is this RNode?\n",
            options: &[
                "[1] Handheld v2.1 RNode, 410 - 525 MHz",
                "[2] Handheld v2.1 RNode, 820 - 1020 MHz",
                "",
                "[3] Original v1.x RNode, 410 - 525 MHz",
                "[4] Original v1.x RNode, 820 - 1020 MHz",
                "",
                "[5] Prototype v2.2 RNode, 410 - 525 MHz",
                "[6] Prototype v2.2 RNode, 820 - 1020 MHz",
            ],
            picks: &[
                Pick::with_mcu(rom::MODEL_A2, rom::MCU_ESP32, ESP32),
                Pick::with_mcu(rom::MODEL_A7, rom::MCU_ESP32, ESP32),
                Pick::on(rom::MODEL_A4, rom::PLATFORM_AVR),
                Pick::on(rom::MODEL_A9, rom::PLATFORM_AVR),
                Pick::with_mcu(rom::MODEL_A1, rom::MCU_ESP32, ESP32),
                Pick::with_mcu(rom::MODEL_A6, rom::MCU_ESP32, ESP32),
            ],
            invalid: BAD_MODEL,
        }],
    },
    ModelQuestions {
        product: rom::PRODUCT_RNODE,
        t3s3: true,
        mcu: None,
        menus: &[Menu {
            question: "\nWhat band is this T3S3 for?\n",
            options: &[
                "[1] 433 MHz         (with SX1278 chip)",
                "[2] 868/915/923 MHz (with SX1276 chip)",
                "",
                "[3] 433 MHz         (with SX1268 chip)",
                "[4] 868/915/923 MHz (with SX1262 chip)",
                "",
                "[5] 2.4 GHz         (with SX1280 chip and PA)",
            ],
            picks: &[
                Pick::with_mcu(rom::MODEL_A5, rom::MCU_ESP32, ESP32),
                Pick::with_mcu(rom::MODEL_AA, rom::MCU_ESP32, ESP32),
                Pick::with_mcu(rom::MODEL_A1, rom::MCU_ESP32, ESP32),
                Pick::with_mcu(rom::MODEL_A6, rom::MCU_ESP32, ESP32),
                Pick::with_mcu(rom::MODEL_AC, rom::MCU_ESP32, ESP32),
            ],
            invalid: BAD_MODEL,
        }],
    },
    ModelQuestions {
        product: rom::PRODUCT_TBEAM,
        t3s3: false,
        mcu: Some(rom::MCU_ESP32),
        menus: &[Menu {
            question: "\nWhat band is this T-Beam for?\n",
            options: &[
                "[1] 433 MHz         (with SX1278 chip)",
                "[2] 868/915/923 MHz (with SX1276 chip)",
                "",
                "[3] 433 MHz         (with SX1268 chip)",
                "[4] 868/915/923 MHz (with SX1262 chip)",
            ],
            picks: &[
                Pick::on(rom::MODEL_E4, ESP32),
                Pick::on(rom::MODEL_E9, ESP32),
                Pick::on(rom::MODEL_E3, ESP32),
                Pick::on(rom::MODEL_E8, ESP32),
            ],
            invalid: BAD_BAND,
        }],
    },
    ModelQuestions {
        product: rom::PRODUCT_TBEAM_S_V1,
        t3s3: false,
        mcu: Some(rom::MCU_ESP32),
        menus: &[Menu {
            question: "\nWhat band is this T-Beam Supreme for?\n",
            options: BANDS_SX126X,
            picks: &[
                Pick::on(rom::MODEL_DB, ESP32),
                Pick::on(rom::MODEL_DC, ESP32),
            ],
            invalid: BAD_BAND,
        }],
    },
    ModelQuestions {
        product: rom::PRODUCT_TDECK,
        t3s3: false,
        mcu: Some(rom::MCU_ESP32),
        menus: &[Menu {
            question: "\nWhat band is this T-Deck for?\n",
            options: BANDS_SX126X,
            picks: &[
                Pick::on(rom::MODEL_D4, ESP32),
                Pick::on(rom::MODEL_D9, ESP32),
            ],
            invalid: BAD_BAND,
        }],
    },
    ModelQuestions {
        product: rom::PRODUCT_T32_10,
        t3s3: false,
        mcu: Some(rom::MCU_ESP32),
        menus: &[Menu {
            question: "\nWhat band is this LoRa32 for?\n",
            options: BANDS_433_868_915_923,
            picks: &split_band(rom::MODEL_BA, rom::MODEL_BB, ESP32),
            invalid: BAD_BAND,
        }],
    },
    ModelQuestions {
        product: rom::PRODUCT_T32_20,
        t3s3: false,
        mcu: Some(rom::MCU_ESP32),
        menus: &[Menu {
            question: "\nWhat band is this LoRa32 for?\n",
            options: BANDS_433_868_915_923,
            picks: &split_band(rom::MODEL_B3, rom::MODEL_B8, ESP32),
            invalid: BAD_BAND,
        }],
    },
    ModelQuestions {
        product: rom::PRODUCT_T32_21,
        t3s3: false,
        mcu: Some(rom::MCU_ESP32),
        menus: &[Menu {
            question: "\nWhat band is this LoRa32 for?\n",
            options: &[
                "[1] 433 MHz",
                "[2] 868/915/923 MHz",
                "[3] 433 MHz, with TCXO",
                "[4] 868/915/923 MHz, with TCXO",
            ],
            picks: &[
                Pick::on(rom::MODEL_B4, ESP32),
                Pick::on(rom::MODEL_B9, ESP32),
                Pick::on(rom::MODEL_B4_TCXO, ESP32),
                Pick::on(rom::MODEL_B9_TCXO, ESP32),
            ],
            invalid: BAD_BAND,
        }],
    },
    ModelQuestions {
        product: rom::PRODUCT_H32_V2,
        t3s3: false,
        mcu: Some(rom::MCU_ESP32),
        menus: &[Menu {
            question: "\nWhat band is this Heltec LoRa32 V2 for?\n",
            options: BANDS_433_868_915_923,
            picks: &split_band(rom::MODEL_C4, rom::MODEL_C9, ESP32),
            invalid: BAD_BAND,
        }],
    },
    ModelQuestions {
        product: rom::PRODUCT_H32_V3,
        t3s3: false,
        mcu: Some(rom::MCU_ESP32),
        menus: &[Menu {
            question: "\nWhat band is this Heltec LoRa32 V3 for?\n",
            options: BANDS_433_868_915_923,
            picks: &split_band(rom::MODEL_C5, rom::MODEL_CA, ESP32),
            invalid: BAD_BAND,
        }],
    },
    ModelQuestions {
        product: rom::PRODUCT_H32_V4,
        t3s3: false,
        mcu: Some(rom::MCU_ESP32),
        menus: &[Menu {
            question: "\nWhat band is this Heltec LoRa32 V4 for?\n",
            options: &[
                "[1] 868 MHz (28 dBm output)",
                "[2] 915 MHz (28 dBm output)",
                "[3] 923 MHz (28 dBm output)",
            ],
            picks: &[Pick::on(rom::MODEL_C8, ESP32); 3],
            invalid: BAD_BAND,
        }],
    },
    ModelQuestions {
        product: rom::PRODUCT_HELTEC_T114,
        t3s3: false,
        mcu: Some(rom::MCU_NRF52),
        menus: &[Menu {
            question: "\nWhat band is this Heltec T114 for?\n",
            options: BANDS_433_868_915_923,
            picks: &split_band(rom::MODEL_C6, rom::MODEL_C7, NRF52),
            invalid: BAD_BAND,
        }],
    },
    ModelQuestions {
        product: rom::PRODUCT_XIAO_S3,
        t3s3: false,
        mcu: Some(rom::MCU_ESP32),
        menus: &[Menu {
            question: "\nWhat band is this XIAO esp32s3 wio module for?\n",
            options: &["[1] 433 MHz", "[2] 868 MHz"],
            picks: &[
                Pick::on(rom::MODEL_DE, ESP32),
                Pick::on(rom::MODEL_DD, ESP32),
            ],
            invalid: BAD_BAND,
        }],
    },
    ModelQuestions {
        product: rom::PRODUCT_RAK4631,
        t3s3: false,
        mcu: Some(rom::MCU_NRF52),
        menus: &[Menu {
            question: "\nWhat band is this RAK4631 for?\n",
            options: BANDS_433_868_915_923,
            picks: &split_band(rom::MODEL_11, rom::MODEL_12, NRF52),
            invalid: BAD_BAND,
        }],
    },
    ModelQuestions {
        product: rom::PRODUCT_TECHO,
        t3s3: false,
        mcu: Some(rom::MCU_NRF52),
        menus: &[Menu {
            question: "\nWhat band is this T-Echo for?\n",
            options: BANDS_433_868_915_923,
            picks: &split_band(rom::MODEL_16, rom::MODEL_17, NRF52),
            invalid: BAD_BAND,
        }],
    },
];

/// upstream's question for a homebrew ESP32 board, picking its firmware.
const ESP32_BOARD: Menu<&str> = Menu {
    question: "\nWhat kind of ESP32 board is this?\n",
    options: &[
        "[1] Adafruit Feather ESP32 (HUZZAH32)",
        "[2] Generic ESP32 board",
    ],
    picks: &[
        "rnode_firmware_featheresp32.zip",
        "rnode_firmware_esp32_generic.zip",
    ],
    invalid: "That ESP32 board does not exist, exiting now.",
};

/// The questions that follow: the model, board or microcontroller of
/// `selected_product`, and the firmware for it.
fn choose_model(selected_product: Option<u8>, c_mod: bool) -> Board {
    let mut board = Board {
        product: selected_product,
        model: None,
        mcu: None,
        platform: None,
        fw_filename: None,
    };
    let questions = MODEL_QUESTIONS
        .iter()
        .find(|questions| selected_product == Some(questions.product) && questions.t3s3 == c_mod);
    if let Some(questions) = questions {
        board.mcu = questions.mcu;
        for menu in questions.menus {
            menu.ask().apply(&mut board);
        }
    }
    board.fw_filename = firmware_filename(&board);
    if board.fw_filename.is_none() {
        println!();
        println!("Sorry, no firmware for your board currently exists.");
        println!("Help making it a reality by contributing code or by");
        println!("donating to the project.");
        println!();
        print_donation_block();
        println!();
        graceful_exit(0);
    }
    board
}

/// The firmware for `board`: its model's, or for a homebrew board, the one
/// for its MCU, asking which ESP32 board it is.
fn firmware_filename(board: &Board) -> Option<String> {
    if board.model != Some(rom::MODEL_FF) && board.model != Some(rom::MODEL_FE) {
        board
            .model
            .and_then(rom::model)
            .and_then(|m| m.firmware)
            .map(str::to_string)
    } else if board.platform == Some(rom::PLATFORM_AVR) {
        match board.mcu {
            Some(rom::MCU_1284P) => Some("rnode_firmware.hex".to_string()),
            Some(rom::MCU_2560) => Some("rnode_firmware_m2560.hex".to_string()),
            _ => None,
        }
    } else if board.platform == Some(rom::PLATFORM_ESP32) {
        Some(ESP32_BOARD.ask().to_string())
    } else {
        None
    }
}

/// The autoinstall wizard up to flashing: pick the port and the board,
/// confirm, and fetch the firmware. Returns the port, the board and the
/// firmware package; flashing, key generation and bootstrapping follow
/// in the main flow, as upstream's wizard hands them on.
pub(crate) fn run(
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
    let opened =
        crate::open_serial(&port).and_then(|(reader, writer)| crate::RNode::new(reader, writer));
    let mut rnode = match opened {
        Ok(rnode) => rnode,
        Err(e) => {
            crate::log_open_failure(&port, &e);
            graceful_exit(0);
        }
    };
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
pub(crate) fn print_completion() {
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
