//! Typed reads of one section's `key = value` pairs.

use super::*;
use std::str::FromStr;

/// The values of one config section, read key by key. An absent key leaves
/// the field as it was; a value that does not parse is
/// [`ConfigError::InvalidValue`] naming the key and the value as written.
pub(super) struct Keys<'a>(pub(super) &'a HashMap<String, String>);

impl<'a> Keys<'a> {
    /// The value of `key` as written.
    pub(super) fn get(&self, key: &str) -> Option<&'a String> {
        self.0.get(key)
    }

    /// The value of `key` as `parse` reads it.
    pub(super) fn with<T>(
        &self,
        key: &str,
        parse: impl FnOnce(&str) -> Option<T>,
    ) -> Result<Option<T>, ConfigError> {
        self.get(key)
            .map(|v| parse(v).ok_or_else(|| invalid(key, v)))
            .transpose()
    }

    /// The value of `key` as a ConfigObj boolean (`yes`, `on`, `1`, ...).
    pub(super) fn bool(&self, key: &str) -> Result<Option<bool>, ConfigError> {
        self.with(key, parse_bool)
    }

    /// The value of `key` through `FromStr`.
    pub(super) fn parse<T: FromStr>(&self, key: &str) -> Result<Option<T>, ConfigError> {
        self.with(key, |v| v.parse().ok())
    }

    /// The value of `key` through `FromStr`, where zero is invalid too.
    pub(super) fn nonzero<T: FromStr + Default + PartialEq>(
        &self,
        key: &str,
    ) -> Result<Option<T>, ConfigError> {
        self.with(key, |v| v.parse().ok().filter(|n| *n != T::default()))
    }

    /// The value of `key` as a non-negative finite number.
    pub(super) fn nonnegative_f64(&self, key: &str) -> Result<Option<f64>, ConfigError> {
        self.with(key, |v| {
            v.parse::<f64>().ok().filter(|n| n.is_finite() && *n >= 0.0)
        })
    }

    /// Set `field` to the boolean value of `key`, if present.
    pub(super) fn set_bool(&self, key: &str, field: &mut bool) -> Result<(), ConfigError> {
        if let Some(v) = self.bool(key)? {
            *field = v;
        }
        Ok(())
    }

    /// Set `field` to the parsed value of `key`, if present.
    pub(super) fn set<T: FromStr>(&self, key: &str, field: &mut T) -> Result<(), ConfigError> {
        if let Some(v) = self.parse(key)? {
            *field = v;
        }
        Ok(())
    }

    /// Set `field` to the parsed value of `key`, if present, rejecting zero.
    pub(super) fn set_nonzero<T: FromStr + Default + PartialEq>(
        &self,
        key: &str,
        field: &mut T,
    ) -> Result<(), ConfigError> {
        if let Some(v) = self.nonzero(key)? {
            *field = v;
        }
        Ok(())
    }

    /// Set `field` to the value of `key` as written, if present.
    pub(super) fn set_string(&self, key: &str, field: &mut Option<String>) {
        if let Some(v) = self.get(key) {
            *field = Some(v.clone());
        }
    }

    /// Add the identity hashes listed in `key` (comma-separated hex) to
    /// `hashes`, skipping empty items and ones already there. An invalid
    /// item is reported on its own.
    pub(super) fn add_identity_hashes(
        &self,
        key: &str,
        hashes: &mut Vec<[u8; 16]>,
    ) -> Result<(), ConfigError> {
        let Some(v) = self.get(key) else {
            return Ok(());
        };
        for hexhash in v.split(',').map(str::trim).filter(|h| !h.is_empty()) {
            let hash = parse_identity_hash_hex(hexhash).ok_or_else(|| invalid(key, hexhash))?;
            if !hashes.contains(&hash) {
                hashes.push(hash);
            }
        }
        Ok(())
    }
}

/// The error for `value`, which is not valid for `key`.
pub(super) fn invalid(key: &str, value: &str) -> ConfigError {
    ConfigError::InvalidValue {
        key: key.into(),
        value: value.into(),
    }
}
