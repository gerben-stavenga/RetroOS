// SPDX-License-Identifier: BSD-3-Clause-Clear
// Regulatory event wire definitions reference Linux ath12k wmi.h/wmi.c.
// Copyright (c) 2021-2025 Qualcomm Innovation Center, Inc. All rights reserved.
//! Firmware regulatory reports, retained without enabling radio transmission.
use super::{Error, Result, required, tlvs, word};
use alloc::vec::Vec;

// Shared WMI structure IDs, independent of PCI ID or firmware version.
const REGULATORY_RULE: u16 = 608;
const REGULATORY_RULE_EXT: u16 = 937;

pub struct Report {
    pub phy: u32,
    pub country: [u8; 2],
    /// Fixed fields retain country/domain, bandwidth, DFS and all 6-GHz groups.
    pub fixed: Vec<u8>,
    /// Counts in firmware wire order: 2G, 5G, LPI/SP/VLP AP, then two client
    /// types for each LPI/SP/VLP group. Reserved client slots are not rules.
    pub counts: [usize; 11],
    /// Raw frequency, bandwidth/power, restriction, and PSD words per rule.
    pub rules: Vec<[u32; 4]>,
    /// Original tag and complete body for each rule, including additive fields
    /// that later protocol/hardware implementations may need to interpret.
    pub raw_rules: Vec<(u16, Vec<u8>)>,
    /// Later ARRAY_STRUCT fields are independent firmware extensions, not
    /// additional regulatory rules. Retain them without changing restrictions.
    pub extensions: Vec<Vec<u8>>,
}
impl Report {
    pub(super) fn parse(values: &[(u16, &[u8])]) -> Result<Self> {
        let fixed = required(values, 938)?;
        if fixed.len() < 78 * 4 {
            return Err(Error::Packet);
        }
        let status = word(fixed, 0)?;
        if status != 0 {
            return Err(Error::Firmware(status));
        }
        let phy = word(fixed, 4)?;
        let num_phy = word(fixed, 12)?;
        if !(1..=8).contains(&num_phy) || phy >= num_phy {
            return Err(Error::Packet);
        }
        let country = [fixed[8], fixed[9]];
        if !country
            .iter()
            .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit())
        {
            return Err(Error::Packet);
        }
        let mut counts = [0usize; 11];
        for (index, field) in [12, 13, 64, 63, 65, 70, 71, 66, 67, 74, 75]
            .iter()
            .enumerate()
        {
            counts[index] = word(fixed, field * 4)? as usize;
            if counts[index] > if index < 2 { 10 } else { 5 } {
                return Err(Error::Packet);
            }
        }
        let total: usize = counts.iter().sum();
        if total == 0 {
            return Err(Error::Packet);
        }
        // ARRAY_STRUCT is a positional container type, not a unique field ID.
        // Linux locates the rule array immediately after the fixed event;
        // later arrays describe separate extensions (observed lengths 8/16).
        let mut arrays = values.iter().filter(|(tag, _)| *tag == 18);
        let array = arrays.next().ok_or(Error::Packet)?.1;
        let entries = tlvs(array)?;
        if entries.len() != total {
            return Err(Error::Packet);
        }
        let mut rules = Vec::new();
        let mut raw_rules = Vec::new();
        for (tag, data) in entries {
            // Firmware may use REGULATORY_RULE_STRUCT with the full extended
            // four-word body. Linux reads this array by record layout rather
            // than requiring REGULATORY_RULE_EXT_STRUCT's tag.
            // Both encodings still require all restriction and PSD fields.
            if !matches!(tag, REGULATORY_RULE | REGULATORY_RULE_EXT) || data.len() < 16 {
                return Err(Error::Packet);
            }
            let rule = [
                word(data, 0)?,
                word(data, 4)?,
                word(data, 8)?,
                word(data, 12)?,
            ];
            let start = rule[0] & 0xffff;
            let end = rule[0] >> 16;
            if start == 0 || end <= start || rule[1] & 0xffff == 0 {
                return Err(Error::Packet);
            }
            rules.push(rule);
            raw_rules.push((tag, data.to_vec()));
        }
        let mut extensions = Vec::new();
        for (_, array) in arrays {
            tlvs(array)?; // ARRAY_STRUCT entries must remain bounded TLVs.
            extensions.push(array.to_vec());
        }
        Ok(Self {
            phy,
            country,
            fixed: fixed.to_vec(),
            counts,
            rules,
            raw_rules,
            extensions,
        })
    }
}
