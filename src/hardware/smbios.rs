//! Minimal SMBIOS (DMI) table parser.
//!
//! Windows exposes the raw SMBIOS table through `GetSystemFirmwareTable`
//! (`RSMB`). The parser is pure and platform independent so the same code is
//! exercised by the Linux test suite with synthetic firmware tables.

use serde::Serialize;

const RAW_SMBIOS_STRUCTURE_OFFSET: usize = 8;

#[derive(Debug, Default, Clone, Serialize)]
pub struct SmbiosData {
    pub bios_vendor: Option<String>,
    pub bios_version: Option<String>,
    pub bios_release_date: Option<String>,
    pub system_manufacturer: Option<String>,
    pub system_product: Option<String>,
    pub system_version: Option<String>,
    pub system_serial: Option<String>,
    pub system_uuid: Option<String>,
    pub board_manufacturer: Option<String>,
    pub board_product: Option<String>,
    pub board_version: Option<String>,
    pub board_serial: Option<String>,
    pub cpu_manufacturer: Option<String>,
    pub cpu_version: Option<String>,
    pub cpu_processor_id: Option<String>,
}

/// Parse the payload returned by `GetSystemFirmwareTable`, including the
/// 8-byte `RawSMBIOSData` header.
pub fn parse_raw(raw: &[u8]) -> Option<SmbiosData> {
    if raw.len() < RAW_SMBIOS_STRUCTURE_OFFSET {
        return None;
    }
    let declared = u32::from_le_bytes([raw[4], raw[5], raw[6], raw[7]]) as usize;
    let available = raw.len() - RAW_SMBIOS_STRUCTURE_OFFSET;
    let length = declared.min(available);
    if length == 0 {
        return None;
    }
    Some(parse_structures(
        &raw[RAW_SMBIOS_STRUCTURE_OFFSET..][..length],
    ))
}

/// Parse a structure table that begins directly with a structure header.
pub fn parse_structures(table: &[u8]) -> SmbiosData {
    let mut data = SmbiosData::default();
    let mut offset = 0usize;

    while offset + 4 <= table.len() {
        let structure_type = table[offset];
        let length = table[offset + 1] as usize;
        if length < 4 || offset + length > table.len() {
            break;
        }
        let formatted = &table[offset..offset + length];
        let (strings, next) = read_strings(table, offset + length);

        match structure_type {
            0 => {
                // BIOS Information
                if data.bios_vendor.is_none() {
                    data.bios_vendor = string(formatted, &strings, 0x04);
                    data.bios_version = string(formatted, &strings, 0x05);
                    data.bios_release_date = string(formatted, &strings, 0x08);
                }
            }
            1 => {
                // System Information
                if data.system_uuid.is_none() && formatted.len() >= 0x18 {
                    data.system_manufacturer = string(formatted, &strings, 0x04);
                    data.system_product = string(formatted, &strings, 0x05);
                    data.system_version = string(formatted, &strings, 0x06);
                    data.system_serial = string(formatted, &strings, 0x07);
                    if let Some(uuid_bytes) = slice(formatted, 0x08, 16) {
                        data.system_uuid = format_uuid(uuid_bytes);
                    }
                }
            }
            2 => {
                // Baseboard Information
                if data.board_serial.is_none() {
                    data.board_manufacturer = string(formatted, &strings, 0x04);
                    data.board_product = string(formatted, &strings, 0x05);
                    data.board_version = string(formatted, &strings, 0x06);
                    data.board_serial = string(formatted, &strings, 0x07);
                }
            }
            4 if data.cpu_processor_id.is_none() => {
                // Processor Information: keep the first processor record.
                data.cpu_manufacturer = string(formatted, &strings, 0x07);
                data.cpu_version = string(formatted, &strings, 0x10);
                if let Some(id) = slice(formatted, 0x08, 8) {
                    if id.iter().any(|byte| *byte != 0) {
                        data.cpu_processor_id =
                            Some(id.iter().map(|byte| format!("{byte:02X}")).collect());
                    }
                }
            }
            _ => {}
        }

        if next <= offset {
            break;
        }
        offset = next;
    }

    data
}

/// Read the NUL-terminated string set that follows a formatted structure area.
/// Returns the strings and the offset of the next structure.
fn read_strings(table: &[u8], mut offset: usize) -> (Vec<&[u8]>, usize) {
    let mut strings = Vec::new();
    loop {
        if offset >= table.len() {
            return (strings, offset);
        }
        if table[offset] == 0 {
            // A zero where a string would start ends the string set. When the
            // set is empty, the structure's additional NUL follows immediately;
            // otherwise this zero is the additional NUL itself.
            let end = if strings.is_empty() {
                offset + 2
            } else {
                offset + 1
            };
            return (strings, end.min(table.len()));
        }
        let start = offset;
        while offset < table.len() && table[offset] != 0 {
            offset += 1;
        }
        strings.push(&table[start..offset]);
        if offset < table.len() {
            offset += 1;
        }
    }
}

fn slice(formatted: &[u8], offset: usize, length: usize) -> Option<&[u8]> {
    formatted.get(offset..offset + length)
}

fn string(formatted: &[u8], strings: &[&[u8]], offset: usize) -> Option<String> {
    let index = *formatted.get(offset)?;
    if index == 0 {
        return None;
    }
    let raw = strings.get(index as usize - 1)?;
    let value = String::from_utf8_lossy(raw).trim().to_string();
    if value.is_empty() {
        None
    } else {
        Some(value)
    }
}

/// SMBIOS encodes the first three UUID fields little-endian.
fn format_uuid(bytes: &[u8]) -> Option<String> {
    if bytes.len() < 16 {
        return None;
    }
    if bytes.iter().all(|byte| *byte == 0) || bytes.iter().all(|byte| *byte == 0xFF) {
        return None;
    }
    Some(format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        bytes[3], bytes[2], bytes[1], bytes[0],
        bytes[5], bytes[4],
        bytes[7], bytes[6],
        bytes[8], bytes[9],
        bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15]
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a structure: header + formatted area + strings + terminating NULs.
    fn structure(structure_type: u8, length: u8, formatted: &[u8], strings: &[&str]) -> Vec<u8> {
        let mut out = vec![structure_type, length, 0x00, 0x00];
        out.extend_from_slice(&formatted[4..]);
        assert_eq!(out.len(), length as usize);
        for value in strings {
            out.extend_from_slice(value.as_bytes());
            out.push(0);
        }
        if strings.is_empty() {
            out.push(0);
        }
        out.push(0);
        out
    }

    #[test]
    fn parses_board_bios_and_system_identity() {
        let uuid = [
            0x33, 0x22, 0x11, 0x00, 0x55, 0x44, 0x77, 0x66, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD,
            0xEE, 0xFF,
        ];

        // Type 0: vendor, version, start segment, release date.
        let mut type0 = vec![0u8; 0x1A];
        type0[0x04] = 1;
        type0[0x05] = 2;
        type0[0x08] = 3;

        // Type 1: manufacturer, product, version, serial, UUID.
        let mut type1 = vec![0u8; 0x1B];
        type1[0x04] = 1;
        type1[0x05] = 2;
        type1[0x06] = 3;
        type1[0x07] = 4;
        type1[0x08..0x18].copy_from_slice(&uuid);

        // Type 2: manufacturer, product, version, serial.
        let mut type2 = vec![0u8; 0x0F];
        type2[0x04] = 1;
        type2[0x05] = 2;
        type2[0x06] = 3;
        type2[0x07] = 4;

        // Type 4: manufacturer, processor id, version.
        let mut type4 = vec![0u8; 0x30];
        type4[0x07] = 1;
        type4[0x08..0x10].copy_from_slice(&[0xA2, 0x0F, 0x0B, 0x00, 1, 2, 3, 4]);
        type4[0x10] = 2;

        let mut table = Vec::new();
        table.extend(structure(0, 0x1A, &type0, &["Vendor", "1.0", "2024-01-02"]));
        table.extend(structure(
            1,
            0x1B,
            &type1,
            &["Board Vendor", "Board Product", "1.0", "SYSTEMSERIAL"],
        ));
        table.extend(structure(
            2,
            0x0F,
            &type2,
            &["Board Vendor", "Board Product", "1.0", "BOARDSERIAL"],
        ));
        table.extend(structure(4, 0x30, &type4, &["CPU Vendor", "Ryzen Test"]));

        let mut raw = vec![0u8; 8];
        raw[1] = 3;
        raw[2] = 5;
        raw[4..8].copy_from_slice(&(table.len() as u32).to_le_bytes());
        raw.extend(table);

        let parsed = parse_raw(&raw).expect("table parses");
        assert_eq!(parsed.bios_vendor.as_deref(), Some("Vendor"));
        assert_eq!(parsed.bios_version.as_deref(), Some("1.0"));
        assert_eq!(parsed.bios_release_date.as_deref(), Some("2024-01-02"));
        assert_eq!(parsed.system_manufacturer.as_deref(), Some("Board Vendor"));
        assert_eq!(parsed.system_serial.as_deref(), Some("SYSTEMSERIAL"));
        assert_eq!(
            parsed.system_uuid.as_deref(),
            Some("00112233-4455-6677-8899-aabbccddeeff")
        );
        assert_eq!(parsed.board_serial.as_deref(), Some("BOARDSERIAL"));
        assert_eq!(parsed.cpu_processor_id.as_deref(), Some("A20F0B0001020304"));
        assert_eq!(parsed.cpu_version.as_deref(), Some("Ryzen Test"));
    }

    #[test]
    fn suppresses_absent_uuid_and_truncated_tables() {
        let mut type1 = vec![0u8; 0x1B];
        type1[0x04] = 1;
        type1[0x08..0x18].copy_from_slice(&[0xFF; 16]);
        let table = structure(1, 0x1B, &type1, &["Only Manufacturer"]);

        let parsed = parse_structures(&table);
        assert_eq!(
            parsed.system_manufacturer.as_deref(),
            Some("Only Manufacturer")
        );
        assert!(parsed.system_uuid.is_none(), "all-0xFF UUID must be absent");

        assert!(parse_raw(&[0, 1, 2]).is_none());
        let truncated = parse_structures(&[0, 2]);
        assert!(truncated.bios_vendor.is_none());
        assert!(truncated.system_uuid.is_none());
        assert!(truncated.board_serial.is_none());
        assert!(truncated.cpu_processor_id.is_none());
    }
}
