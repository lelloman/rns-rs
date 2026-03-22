use crate::control::ble_open_control_default;

pub const SETTINGS_BLOB_LEN: usize = 2;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DeviceSettings {
    pub ble_open_control: bool,
}

impl DeviceSettings {
    pub fn compile_default() -> Self {
        Self {
            ble_open_control: ble_open_control_default(),
        }
    }

    pub fn encode(self) -> [u8; SETTINGS_BLOB_LEN] {
        [1, u8::from(self.ble_open_control)]
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SettingsDecodeError {
    InvalidLength(usize),
    UnsupportedVersion(u8),
    InvalidBleFlag(u8),
}

pub fn decode_settings(raw: Option<&[u8]>) -> Result<Option<DeviceSettings>, SettingsDecodeError> {
    let Some(raw) = raw else {
        return Ok(None);
    };
    if raw.len() != SETTINGS_BLOB_LEN {
        return Err(SettingsDecodeError::InvalidLength(raw.len()));
    }
    if raw[0] != 1 {
        return Err(SettingsDecodeError::UnsupportedVersion(raw[0]));
    }

    let ble_open_control = match raw[1] {
        0 => false,
        1 => true,
        other => return Err(SettingsDecodeError::InvalidBleFlag(other)),
    };

    Ok(Some(DeviceSettings { ble_open_control }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_settings() {
        let settings = DeviceSettings {
            ble_open_control: true,
        };
        let encoded = settings.encode();
        assert_eq!(decode_settings(Some(&encoded)).unwrap(), Some(settings));
    }

    #[test]
    fn rejects_wrong_length() {
        assert_eq!(
            decode_settings(Some(&[1u8])).unwrap_err(),
            SettingsDecodeError::InvalidLength(1)
        );
    }

    #[test]
    fn rejects_invalid_flag() {
        assert_eq!(
            decode_settings(Some(&[1u8, 2u8])).unwrap_err(),
            SettingsDecodeError::InvalidBleFlag(2)
        );
    }
}
