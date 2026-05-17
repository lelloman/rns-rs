use alloc::string::String;

const B256: [&str; 256] = [
    "a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k", "l", "m", "n", "o", "p", "q", "r", "s",
    "t", "u", "v", "x", "y", "z", "æ", "ø", "0", "1", "2", "3", "4", "A", "B", "C", "D", "E", "F",
    "G", "H", "I", "J", "K", "L", "M", "N", "O", "P", "Q", "R", "S", "T", "U", "W", "X", "Y", "Z",
    "Æ", "Ø", "5", "6", "7", "8", "9", "α", "β", "γ", "δ", "ε", "ζ", "η", "θ", "ι", "κ", "λ", "μ",
    "ν", "ξ", "π", "ρ", "σ", "τ", "φ", "χ", "ψ", "ω", "Γ", "Δ", "Θ", "Λ", "Ξ", "Π", "Σ", "Φ", "Ψ",
    "Ω", "Б", "Д", "Ж", "З", "И", "Л", "П", "Ц", "Ч", "Ш", "Щ", "Ъ", "Ы", "Э", "Ю", "Я", "б", "д",
    "ж", "з", "и", "л", "п", "ц", "ч", "ш", "щ", "ъ", "ы", "э", "ю", "я", "Ա", "Բ", "Գ", "Դ", "Ե",
    "Զ", "Է", "Ը", "Թ", "Ժ", "Ի", "Խ", "Ծ", "Կ", "Հ", "Ձ", "Ղ", "Ճ", "Մ", "Յ", "Ն", "Շ", "Ո", "Չ",
    "Պ", "Ջ", "Վ", "Ր", "Ց", "Ւ", "Ք", "Ֆ", "ᚠ", "ᚢ", "ᚦ", "ᚱ", "ᚹ", "ᚺ", "ᚾ", "ᛈ", "ᛇ", "ᛉ", "ᛊ",
    "ᛏ", "ᛒ", "ᛖ", "ᛗ", "ᛟ", "ｲ", "ｳ", "ｵ", "ｶ", "ｷ", "ｹ", "ｻ", "ｼ", "ｽ", "ｾ", "ﾀ", "ﾁ", "ﾃ", "ﾄ",
    "ﾅ", "ﾇ", "ﾈ", "ﾋ", "ﾌ", "ﾍ", "ﾎ", "ﾏ", "ﾐ", "ﾑ", "ﾒ", "ﾓ", "ﾔ", "ﾗ", "ﾘ", "ﾙ", "ﾚ", "ﾜ", "𐑐",
    "𐑑", "𐑒", "𐑔", "𐑕", "𐑗", "𐑙", "𐑳", "𐑶", "𐑸", "𐑹", "𐑺", "𐑻", "𐑽", "𐑾", "𐑿", "᱑", "᱕", "᱘", "᱙",
    "ᱚ", "ᱝ", "ᱟ", "ᱣ", "ᱦ", "ᱨ", "ᱬ", "ᱭ", "ᱰ", "ᱳ", "ᱶ", "ᱷ", "𐌳", "𐌸", "𐌾", "𐐀", "𐐁", "𐐂", "𐐆",
    "𐐇", "𐐈", "𐐉", "𐐊", "𐐋", "𐐌", "𐐍", "𐐎", "𐐏",
];

/// Return the upstream base256 display glyph for a byte.
pub fn b256_rep(byte: u8) -> &'static str {
    B256[byte as usize]
}

/// Encode bytes with the upstream experimental base256 glyph table.
pub fn b256rep(data: &[u8]) -> String {
    let mut out = String::new();
    for byte in data {
        out.push_str(b256_rep(*byte));
    }
    out
}

/// Format bytes using upstream `prettyb256rep()` display form.
pub fn prettyb256rep(data: &[u8]) -> String {
    let mut out = String::from("<");
    out.push_str(&b256rep(data));
    out.push('>');
    out
}

/// Decode an upstream experimental base256 glyph string back to bytes.
pub fn b256_to_bytes(input: &str) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    for ch in input.chars() {
        let index = B256.iter().position(|point| {
            let mut chars = point.chars();
            chars.next() == Some(ch) && chars.next().is_none()
        })?;
        out.push(index as u8);
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prettyb256rep_matches_upstream_map_edges() {
        assert_eq!(prettyb256rep(&[0x00, 0x1a, 0x1b, 0x3f]), "<aø09>");
        assert_eq!(prettyb256rep(&[0x40, 0x5f, 0xff]), "<αΩ𐐏>");
    }

    #[test]
    fn b256_rep_covers_all_bytes() {
        for byte in 0u8..=255 {
            assert!(!b256_rep(byte).is_empty());
        }
    }

    #[test]
    fn b256rep_roundtrips_all_bytes() {
        let data = (0u8..=255).collect::<Vec<_>>();
        let encoded = b256rep(&data);
        assert_eq!(b256_to_bytes(&encoded).unwrap(), data);
        assert_eq!(b256_to_bytes("not/base256"), None);
    }
}
