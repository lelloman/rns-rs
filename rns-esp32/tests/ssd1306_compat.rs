use std::cell::RefCell;
use std::rc::Rc;

use embedded_graphics::mono_font::ascii::FONT_6X10;
use embedded_graphics::mono_font::MonoTextStyle;
use embedded_graphics::pixelcolor::BinaryColor;
use embedded_graphics::prelude::*;
use embedded_graphics::text::Text;
use embedded_hal::i2c::{ErrorKind, ErrorType, I2c, Operation};
use ssd1306::prelude::*;
use ssd1306::size::DisplaySize128x64;
use ssd1306::{I2CDisplayInterface, Ssd1306};

const OLED_ADDRESS: u8 = 0x3c;
const COMMAND_CONTROL_BYTE: u8 = 0x00;
const DATA_CONTROL_BYTE: u8 = 0x40;
const FRAMEBUFFER_LEN: usize = 128 * 64 / 8;

#[derive(Clone, Debug)]
struct RecordingI2c {
    writes: Rc<RefCell<Vec<(u8, Vec<u8>)>>>,
    fail_after: Option<usize>,
}

impl RecordingI2c {
    fn new() -> (Self, Rc<RefCell<Vec<(u8, Vec<u8>)>>>) {
        let writes = Rc::new(RefCell::new(Vec::new()));
        (
            Self {
                writes: Rc::clone(&writes),
                fail_after: None,
            },
            writes,
        )
    }

    fn failing() -> Self {
        Self {
            writes: Rc::new(RefCell::new(Vec::new())),
            fail_after: Some(0),
        }
    }

    fn record_write(&self, address: u8, bytes: &[u8]) -> Result<(), ErrorKind> {
        let mut writes = self.writes.borrow_mut();
        if self.fail_after.is_some_and(|limit| writes.len() >= limit) {
            return Err(ErrorKind::Other);
        }
        writes.push((address, bytes.to_vec()));
        Ok(())
    }
}

impl ErrorType for RecordingI2c {
    type Error = ErrorKind;
}

impl I2c for RecordingI2c {
    fn transaction(
        &mut self,
        address: u8,
        operations: &mut [Operation<'_>],
    ) -> Result<(), Self::Error> {
        for operation in operations {
            match operation {
                Operation::Read(bytes) => bytes.fill(0),
                Operation::Write(bytes) => self.record_write(address, bytes)?,
            }
        }
        Ok(())
    }
}

fn display(
    i2c: RecordingI2c,
) -> ssd1306::Ssd1306<
    ssd1306::prelude::I2CInterface<RecordingI2c>,
    DisplaySize128x64,
    ssd1306::mode::BufferedGraphicsMode<DisplaySize128x64>,
> {
    Ssd1306::new(
        I2CDisplayInterface::new(i2c),
        DisplaySize128x64,
        DisplayRotation::Rotate0,
    )
    .into_buffered_graphics_mode()
}

fn payloads_with_control(writes: &[(u8, Vec<u8>)], control: u8) -> Vec<u8> {
    writes
        .iter()
        .filter_map(|(address, bytes)| {
            assert_eq!(*address, OLED_ADDRESS);
            (bytes.first() == Some(&control)).then_some(&bytes[1..])
        })
        .flatten()
        .copied()
        .collect()
}

#[test]
fn initializes_128x64_display_at_default_address() {
    let (i2c, writes) = RecordingI2c::new();
    display(i2c).init().expect("display initialization");

    let writes = writes.borrow();
    assert!(!writes.is_empty());
    assert!(writes.iter().all(|(address, _)| *address == OLED_ADDRESS));

    let commands = payloads_with_control(&writes, COMMAND_CONTROL_BYTE);
    assert_eq!(commands.first(), Some(&0xae), "initialization starts off");
    assert!(commands.windows(2).any(|bytes| bytes == [0xa8, 0x3f]));
    assert!(commands.windows(2).any(|bytes| bytes == [0x20, 0x00]));
    assert_eq!(commands.last(), Some(&0xaf), "initialization ends on");
}

#[test]
fn emits_power_and_brightness_commands_used_by_firmware() {
    let (i2c, writes) = RecordingI2c::new();
    let mut display = display(i2c);

    display.set_display_on(false).expect("display off");
    display.set_display_on(true).expect("display on");
    display
        .set_brightness(Brightness::BRIGHTEST)
        .expect("brightness");

    let commands = payloads_with_control(&writes.borrow(), COMMAND_CONTROL_BYTE);
    assert_eq!(commands, [0xae, 0xaf, 0xd9, 0x21, 0x81, 0xff]);
}

#[test]
fn flushes_page_ordered_pixels_and_text_in_bounded_i2c_chunks() {
    let (i2c, writes) = RecordingI2c::new();
    let mut display = display(i2c);
    display.clear_buffer();

    Pixel(Point::new(0, 0), BinaryColor::On)
        .draw(&mut display)
        .expect("top-left pixel");
    Pixel(Point::new(127, 7), BinaryColor::On)
        .draw(&mut display)
        .expect("first-page pixel");
    Pixel(Point::new(5, 8), BinaryColor::On)
        .draw(&mut display)
        .expect("second-page pixel");
    Pixel(Point::new(127, 63), BinaryColor::On)
        .draw(&mut display)
        .expect("bottom-right pixel");
    Text::new(
        "RNS",
        Point::new(16, 20),
        MonoTextStyle::new(&FONT_6X10, BinaryColor::On),
    )
    .draw(&mut display)
    .expect("firmware-style text");

    display.flush().expect("framebuffer flush");

    let writes = writes.borrow();
    let data_writes: Vec<_> = writes
        .iter()
        .filter(|(_, bytes)| bytes.first() == Some(&DATA_CONTROL_BYTE))
        .collect();
    assert_eq!(data_writes.len(), FRAMEBUFFER_LEN / 16);
    assert!(data_writes.iter().all(|(_, bytes)| bytes.len() == 17));

    let framebuffer = payloads_with_control(&writes, DATA_CONTROL_BYTE);
    assert_eq!(framebuffer.len(), FRAMEBUFFER_LEN);
    assert_eq!(framebuffer[0], 0x01);
    assert_eq!(framebuffer[127], 0x80);
    assert_eq!(framebuffer[128 + 5], 0x01);
    assert_eq!(framebuffer[7 * 128 + 127], 0x80);
    assert!(framebuffer[2 * 128 + 16..4 * 128]
        .iter()
        .any(|byte| *byte != 0));
}

#[test]
fn clear_buffer_flushes_a_zeroed_full_frame() {
    let (i2c, writes) = RecordingI2c::new();
    let mut display = display(i2c);
    display.clear_buffer();
    display.flush().expect("cleared framebuffer flush");

    let framebuffer = payloads_with_control(&writes.borrow(), DATA_CONTROL_BYTE);
    assert_eq!(framebuffer, vec![0; FRAMEBUFFER_LEN]);
}

#[test]
fn reports_i2c_bus_failures_from_commands_and_flushes() {
    let mut command_display = display(RecordingI2c::failing());
    assert!(command_display.init().is_err());
    assert!(command_display.set_display_on(true).is_err());

    let mut flush_display = display(RecordingI2c::failing());
    flush_display.clear_buffer();
    assert!(flush_display.flush().is_err());
}
