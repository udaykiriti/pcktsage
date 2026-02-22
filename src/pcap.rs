use std::fs::File;
use std::io::{BufWriter, Write};
use std::time::{SystemTime, UNIX_EPOCH};

pub struct PcapWriter {
    writer: BufWriter<File>,
}

impl PcapWriter {
    pub fn create(path: &str) -> Result<Self, String> {
        let file = File::create(path).map_err(|e| format!("failed to create pcap file: {e}"))?;
        let mut writer = BufWriter::new(file);

        // PCAP global header (little-endian, Ethernet link type).
        write_u32(&mut writer, 0xA1B2C3D4)?;
        write_u16(&mut writer, 2)?;
        write_u16(&mut writer, 4)?;
        write_i32(&mut writer, 0)?;
        write_u32(&mut writer, 0)?;
        write_u32(&mut writer, 65535)?;
        write_u32(&mut writer, 1)?;

        Ok(Self { writer })
    }

    pub fn write_frame(&mut self, frame: &[u8]) -> Result<(), String> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| format!("system time error: {e}"))?;
        let ts_sec = now.as_secs() as u32;
        let ts_usec = now.subsec_micros();
        let incl_len = frame.len() as u32;
        let orig_len = incl_len;

        write_u32(&mut self.writer, ts_sec)?;
        write_u32(&mut self.writer, ts_usec)?;
        write_u32(&mut self.writer, incl_len)?;
        write_u32(&mut self.writer, orig_len)?;
        self.writer
            .write_all(frame)
            .map_err(|e| format!("failed to write frame: {e}"))
    }

    pub fn flush(&mut self) -> Result<(), String> {
        self.writer
            .flush()
            .map_err(|e| format!("failed to flush pcap writer: {e}"))
    }
}

fn write_u16<W: Write>(w: &mut W, value: u16) -> Result<(), String> {
    w.write_all(&value.to_le_bytes())
        .map_err(|e| format!("pcap write error: {e}"))
}

fn write_u32<W: Write>(w: &mut W, value: u32) -> Result<(), String> {
    w.write_all(&value.to_le_bytes())
        .map_err(|e| format!("pcap write error: {e}"))
}

fn write_i32<W: Write>(w: &mut W, value: i32) -> Result<(), String> {
    w.write_all(&value.to_le_bytes())
        .map_err(|e| format!("pcap write error: {e}"))
}
