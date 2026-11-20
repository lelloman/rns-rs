use super::*;

#[test]
fn python_number_formatting() {
    assert_eq!(py_float(410000000.0 / 1e6), "410.0");
    assert_eq!(py_float(867200000.0 / 1_000_000.0), "867.2");
    assert_eq!(py_float(125000.0 / 1000.0), "125.0");
    assert_eq!(py_float(py_round(10f64.powf(1.4), 3)), "25.119");
    assert_eq!(py_float(py_round(5.46875, 2)), "5.47");
    assert_eq!(hexrep(&[0xde, 0xad, 0x01]), "de:ad:01");
}

#[test]
fn an_nrf52_board_is_found_again_by_its_usb_serial_number() {
    // A port that is not listed is the first candidate, matched by the
    // missing serial number upstream would see for it.
    assert_eq!(
        find_port_after_reset("/nonexistent/pty", &None).as_deref(),
        Some("/nonexistent/pty")
    );
    assert_eq!(
        find_port_after_reset("/nonexistent/pty", &Some("no-such-serial".into())),
        None
    );
}
