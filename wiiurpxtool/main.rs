#!/usr/bin/env -S cargo +nightly -q -Zscript
---cargo
[package]
name = "wiiurpxtool"
version = "0.1.0"
edition = "2024"
# repository = https://github.com/0CBH0/wiiurpxtool

[dependencies]
clap = { version = "4.4", features = ["derive"] }
flate2 = "1.0"
stderrlog = "0.6"
---

use clap::{ArgAction, Parser, Subcommand};
use flate2::{Compression, read::ZlibDecoder, write::ZlibEncoder};
use std::{
    borrow::Cow,
    env,
    fs,
    io::{self, Read, Write},
    path::{Path, PathBuf},
    process::ExitCode,
    sync::atomic::{AtomicU8, Ordering},
};

const SHF_RPL_ZLIB: u32 = 0x0800_0000;
const SHT_NOBITS: u32 = 8;
const SHT_RPL_EXPORTS: u32 = 0x8000_0001;
const SHT_RPL_IMPORTS: u32 = 0x8000_0002;
const SHT_RPL_CRCS: u32 = 0x8000_0003;
const SHT_RPL_FILEINFO: u32 = 0x8000_0004;
const LEVEL: u32 = 6;

const EHDR_SIZE: usize = 0x34;
const SHDR_SIZE: usize = 40;
const SECTION_ALIGN: usize = 0x40;

// ───────────────────────── ログ ─────────────────────────
// 0 = 出力なし (-q) / 1 = info (既定) / 2 = debug (-v) / 3 = trace (-vv)
// ログは stderr に出力し、-p の解析結果 (stdout) とは分離する。

static LOG_LEVEL: AtomicU8 = AtomicU8::new(1);

macro_rules! info {
    ($($a:tt)*) => {
        if LOG_LEVEL.load(Ordering::Relaxed) >= 1 {
            eprintln!("[INFO]  {}", format!($($a)*));
        }
    };
}
macro_rules! debug {
    ($($a:tt)*) => {
        if LOG_LEVEL.load(Ordering::Relaxed) >= 2 {
            eprintln!("[DEBUG] {}", format!($($a)*));
        }
    };
}
macro_rules! trace {
    ($($a:tt)*) => {
        if LOG_LEVEL.load(Ordering::Relaxed) >= 3 {
            eprintln!("[TRACE] {}", format!($($a)*));
        }
    };
}

// ───────────────────────── コマンドライン ─────────────────────────

#[derive(Parser, Debug)]
#[command(
    name = "wiiurpxtool",
    about = "Wii U の RPL/RPX ファイルを圧縮・展開・解析するツール",
    override_usage = "wiiurpxtool [OPTIONS] <COMMAND> [入力ファイル] [出力ファイル]",
    after_help = "使用例:\n  wiiurpxtool compress   -i game.elf -o game.rpx\n  wiiurpxtool decompress -i=game.rpx -o=game_dec.elf\n  wiiurpxtool parse game.rpx\n  wiiurpxtool -vv decompress game.rpx"
)]
struct Args {
    /// 入力ファイル
    #[arg(short = 'i', long, value_name = "PATH", global = true, help = "入力ファイル")]
    input: Option<PathBuf>,

    /// 出力ファイル
    #[arg(
        short = 'o',
        long,
        value_name = "PATH",
        global = true,
        help = "出力ファイル (省略時は入力ファイルを上書き)"
    )]
    output: Option<PathBuf>,

    #[arg(
        short = 'v',
        long,
        global = true,
        action = ArgAction::Count,
        help = "ログを詳細にする (-v: debug, -vv: trace)"
    )]
    verbose: u8,

    #[arg(short = 'q', long, global = true, help = "ログを出力しない")]
    quiet: bool,

    #[command(subcommand)]
    command: Cmd,
}

#[derive(Subcommand, Debug)]
enum Cmd {
    /// 圧縮する (例: -i game.elf -o game.rpx)
    #[command(
        alias = "crypt",
        after_help = "使用例:\n  wiiurpxtool compress --input game.elf --output game.rpx\n  wiiurpxtool compress game.elf game.rpx\n  wiiurpxtool compress game.elf            (入力ファイルを上書き)\n\n別名: crypt"
    )]
    Compress {
        #[arg(value_name = "入力ファイル")]
        input_pos: Option<PathBuf>,
        #[arg(value_name = "出力ファイル")]
        output_pos: Option<PathBuf>,
    },

    /// 展開する (例: -i=game.rpx -o=game_dec.elf)
    #[command(
        alias = "decrypt",
        after_help = "使用例:\n  wiiurpxtool decompress -i=game.rpx -o=game_dec.elf\n  wiiurpxtool decompress game.rpx game_dec.elf\n  wiiurpxtool decompress game.rpx            (入力ファイルを上書き)\n\n別名: decrypt"
    )]
    Decompress {
        #[arg(value_name = "入力ファイル")]
        input_pos: Option<PathBuf>,
        #[arg(value_name = "出力ファイル")]
        output_pos: Option<PathBuf>,
    },

    /// 内部構造を詳細に解析して表示する (ファイルは変更しない)
    Parse {
        #[arg(value_name = "PATH")]
        path: Option<PathBuf>,
    },
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    Compress,
    Decompress,
}

// ───────────────────────── データ構造 ─────────────────────────

#[derive(Clone, Copy, Default)]
struct Shdr {
    name: u32,
    kind: u32,
    flags: u32,
    addr: u32,
    offset: u32,
    size: u32,
    link: u32,
    info: u32,
    addralign: u32,
    entsize: u32,
}

impl Shdr {
    fn parse(d: &[u8], off: usize) -> io::Result<Self> {
        let f = |i: usize| be32(d, off + i * 4);
        Ok(Self {
            name: f(0)?,
            kind: f(1)?,
            flags: f(2)?,
            addr: f(3)?,
            offset: f(4)?,
            size: f(5)?,
            link: f(6)?,
            info: f(7)?,
            addralign: f(8)?,
            entsize: f(9)?,
        })
    }

    fn write(&self, out: &mut [u8], off: usize) {
        let vals = [
            self.name,
            self.kind,
            self.flags,
            self.addr,
            self.offset,
            self.size,
            self.link,
            self.info,
            self.addralign,
            self.entsize,
        ];
        for (i, v) in vals.iter().enumerate() {
            out[off + i * 4..off + i * 4 + 4].copy_from_slice(&v.to_be_bytes());
        }
    }
}

struct Layout {
    machine: u16,
    entry: u32,
    phoff: u32,
    shoff: usize,
    flags: u32,
    shnum: usize,
    shstrndx: usize,
    shdrs: Vec<Shdr>,
}

// ───────────────────────── 共通ユーティリティ ─────────────────────────

fn bad(msg: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg.to_string())
}

fn slice(d: &[u8], off: usize, len: usize) -> io::Result<&[u8]> {
    let end = off.checked_add(len).ok_or_else(|| bad("オフセットがオーバーフローしました"))?;
    d.get(off..end)
        .ok_or_else(|| bad("ファイルが途中で切れているか、破損しています"))
}

fn be16(d: &[u8], off: usize) -> io::Result<u16> {
    Ok(u16::from_be_bytes(slice(d, off, 2)?.try_into().unwrap()))
}

fn be32(d: &[u8], off: usize) -> io::Result<u32> {
    Ok(u32::from_be_bytes(slice(d, off, 4)?.try_into().unwrap()))
}

const CRC_TABLE: [u32; 256] = {
    let mut t = [0u32; 256];
    let mut i = 0;
    while i < 256 {
        let mut c = i as u32;
        let mut k = 0;
        while k < 8 {
            c = if c & 1 != 0 { 0xEDB8_8320 ^ (c >> 1) } else { c >> 1 };
            k += 1;
        }
        t[i] = c;
        i += 1;
    }
    t
};

fn crc32_rpx(crc: u32, buf: &[u8]) -> u32 {
    let mut c = !crc;
    for &b in buf {
        c = (c >> 8) ^ CRC_TABLE[((c as u8) ^ b) as usize];
    }
    !c
}

/// RPX の zlib セクション: [u32 BE 展開後サイズ][zlib ストリーム]
fn inflate_section(raw: &[u8]) -> io::Result<Vec<u8>> {
    if raw.len() < 4 {
        return Err(bad("圧縮セクションが小さすぎます"));
    }
    let decomp_size = be32(raw, 0)? as usize;
    let mut buf = Vec::with_capacity(decomp_size);
    ZlibDecoder::new(&raw[4..]).read_to_end(&mut buf)?;
    if buf.len() != decomp_size {
        return Err(bad("展開後のサイズがヘッダの値と一致しません"));
    }
    Ok(buf)
}

fn deflate(data: &[u8]) -> io::Result<Vec<u8>> {
    let mut enc = ZlibEncoder::new(Vec::new(), Compression::new(LEVEL));
    enc.write_all(data)?;
    enc.finish()
}

fn pad_to_align(out: &mut Vec<u8>) {
    let rem = out.len() % SECTION_ALIGN;
    if rem != 0 {
        out.resize(out.len() + SECTION_ALIGN - rem, 0);
    }
}

fn yn(b: bool) -> &'static str {
    if b { "あり" } else { "なし" }
}

/// ELF ヘッダとセクションヘッダテーブルを読み込む
fn read_layout(input: &[u8]) -> io::Result<Layout> {
    if slice(input, 0, 4)? != [0x7F, b'E', b'L', b'F'] {
        return Err(bad("ELF ファイルではありません"));
    }
    if be16(input, 16)? != 0xFE01 {
        return Err(bad("RPL/RPX ファイルではありません (e_type が 0xFE01 ではありません)"));
    }

    let shoff = be32(input, 0x20)? as usize;
    let shentsize = be16(input, 0x2E)? as usize;
    let shnum = be16(input, 0x30)? as usize;
    if shentsize != SHDR_SIZE {
        return Err(bad("セクションヘッダのサイズが想定外です"));
    }
    if shoff < EHDR_SIZE {
        return Err(bad("セクションヘッダのオフセットが不正です"));
    }

    let mut shdrs = Vec::with_capacity(shnum);
    for i in 0..shnum {
        shdrs.push(Shdr::parse(input, shoff + i * SHDR_SIZE)?);
    }

    let lay = Layout {
        machine: be16(input, 18)?,
        entry: be32(input, 24)?,
        phoff: be32(input, 28)?,
        shoff,
        flags: be32(input, 36)?,
        shnum,
        shstrndx: be16(input, 0x32)? as usize,
        shdrs,
    };
    debug!(
        "ELF ヘッダ: セクション数={} セクションヘッダ位置=0x{:X} shstrndx={}",
        lay.shnum, lay.shoff, lay.shstrndx
    );
    Ok(lay)
}

// ───────────────────────── 圧縮 / 展開 ─────────────────────────

fn process(input: &[u8], mode: Mode) -> io::Result<Vec<u8>> {
    let lay = read_layout(input)?;
    let e_shoff = lay.shoff;
    let e_shnum = lay.shnum;
    let mut shdrs = lay.shdrs;

    let shdr_end = e_shoff
        .checked_add(e_shnum * SHDR_SIZE)
        .ok_or_else(|| bad("セクションヘッダテーブルがオーバーフローしました"))?;

    // ELF ヘッダ + セクションヘッダテーブルまでをゼロ埋め
    let mut out = Vec::with_capacity(input.len());
    out.extend_from_slice(&input[..EHDR_SIZE]);
    out.resize(shdr_end.max(0x40), 0);

    let mut order: Vec<usize> = (0..e_shnum).filter(|&i| shdrs[i].offset != 0).collect();
    order.sort_by_key(|&i| shdrs[i].offset); // 安定ソート
    debug!("処理対象セクション数: {} / {}", order.len(), e_shnum);

    let mut crcs = vec![0u32; e_shnum];
    let mut crc_data_offset: Option<usize> = None;

    for &idx in &order {
        let sh = shdrs[idx];
        let raw = slice(input, sh.offset as usize, sh.size as usize)?;
        let new_off = out.len();
        if new_off > u32::MAX as usize {
            return Err(bad("出力サイズが大きすぎます"));
        }
        let is_zlib = sh.flags & SHF_RPL_ZLIB != 0;

        match mode {
            Mode::Decompress => {
                if is_zlib {
                    let data = inflate_section(raw)?;
                    crcs[idx] = crc32_rpx(0, &data);
                    out.extend_from_slice(&data);
                    shdrs[idx].size = data.len() as u32;
                    shdrs[idx].flags &= !SHF_RPL_ZLIB;
                } else {
                    crcs[idx] = crc32_rpx(0, raw);
                    out.extend_from_slice(raw);
                }
            }
            Mode::Compress => {
                if is_zlib {
                    // すでに圧縮済み: そのままコピー (CRC は展開後データから計算)
                    crcs[idx] = crc32_rpx(0, &inflate_section(raw)?);
                    out.extend_from_slice(raw);
                } else if sh.kind == SHT_RPL_FILEINFO || sh.kind == SHT_RPL_CRCS {
                    crcs[idx] = crc32_rpx(0, raw);
                    out.extend_from_slice(raw);
                } else {
                    crcs[idx] = crc32_rpx(0, raw);
                    let comp = deflate(raw)?;
                    if comp.len() + 4 < raw.len() {
                        out.extend_from_slice(&(raw.len() as u32).to_be_bytes());
                        out.extend_from_slice(&comp);
                        shdrs[idx].size = (comp.len() + 4) as u32;
                        shdrs[idx].flags |= SHF_RPL_ZLIB;
                    } else {
                        debug!("セクション #{idx}: 圧縮の効果がないため無圧縮のまま格納します");
                        out.extend_from_slice(raw);
                    }
                }
            }
        }

        debug!(
            "セクション #{idx} [{}]: オフセット 0x{:X} → 0x{:X}, サイズ {} → {}, zlib {} → {}",
            type_name(sh.kind),
            sh.offset,
            new_off,
            sh.size,
            shdrs[idx].size,
            yn(is_zlib),
            yn(shdrs[idx].flags & SHF_RPL_ZLIB != 0)
        );
        trace!("  セクション #{idx}: CRC32 = {:08X}", crcs[idx]);

        shdrs[idx].offset = new_off as u32;
        pad_to_align(&mut out);

        if sh.kind == SHT_RPL_CRCS {
            crcs[idx] = 0;
            crc_data_offset = Some(new_off);
            debug!("CRC セクションを検出: 新オフセット 0x{new_off:X}");
        }
    }

    for (i, sh) in shdrs.iter().enumerate() {
        sh.write(&mut out, e_shoff + i * SHDR_SIZE);
    }
    trace!("セクションヘッダテーブルを書き込みました ({} 個)", shdrs.len());

    if let Some(off) = crc_data_offset {
        if off + e_shnum * 4 > out.len() {
            return Err(bad("CRC セクションが小さすぎます"));
        }
        for (i, c) in crcs.iter().enumerate() {
            out[off + i * 4..off + i * 4 + 4].copy_from_slice(&c.to_be_bytes());
        }
        debug!("CRC テーブルを書き込みました");
    } else {
        debug!("CRC セクションが無いため CRC テーブルは書き込みません");
    }

    Ok(out)
}

// ───────────────────────── 詳細解析 (parse) ─────────────────────────

fn section_data<'a>(input: &'a [u8], sh: &Shdr) -> io::Result<Cow<'a, [u8]>> {
    let raw = slice(input, sh.offset as usize, sh.size as usize)?;
    if sh.flags & SHF_RPL_ZLIB != 0 {
        Ok(Cow::Owned(inflate_section(raw)?))
    } else {
        Ok(Cow::Borrowed(raw))
    }
}

fn type_name(k: u32) -> String {
    match k {
        0 => "NULL".into(),
        1 => "PROGBITS".into(),
        2 => "SYMTAB".into(),
        3 => "STRTAB".into(),
        4 => "RELA".into(),
        5 => "HASH".into(),
        6 => "DYNAMIC".into(),
        7 => "NOTE".into(),
        SHT_NOBITS => "NOBITS".into(),
        9 => "REL".into(),
        SHT_RPL_EXPORTS => "RPL_EXPORTS".into(),
        SHT_RPL_IMPORTS => "RPL_IMPORTS".into(),
        SHT_RPL_CRCS => "RPL_CRCS".into(),
        SHT_RPL_FILEINFO => "RPL_FILEINFO".into(),
        _ => format!("0x{k:08X}"),
    }
}

fn flag_str(f: u32) -> String {
    let mut s = String::new();
    if f & 1 != 0 {
        s.push('W');
    }
    if f & 2 != 0 {
        s.push('A');
    }
    if f & 4 != 0 {
        s.push('X');
    }
    if f & SHF_RPL_ZLIB != 0 {
        s.push('Z');
    }
    if s.is_empty() { "-".into() } else { s }
}

/// 全角文字を 2 桁として数えた表示幅
fn disp_width(s: &str) -> usize {
    s.chars().map(|c| if c.is_ascii() { 1 } else { 2 }).sum()
}

fn pad(s: &str, width: usize) -> String {
    let w = disp_width(s);
    format!("{s}{}", " ".repeat(width.saturating_sub(w)))
}

fn print_table(header: &[&str], rows: &[Vec<String>]) {
    let cols = header.len();
    let mut widths: Vec<usize> = header.iter().map(|h| disp_width(h)).collect();
    for r in rows {
        for (i, c) in r.iter().enumerate() {
            widths[i] = widths[i].max(disp_width(c));
        }
    }
    let line = |cells: Vec<&str>| {
        let mut s = String::new();
        for i in 0..cols {
            s.push_str(&pad(cells[i], widths[i]));
            if i + 1 < cols {
                s.push_str("  ");
            }
        }
        println!("{}", s.trim_end());
    };
    line(header.to_vec());
    println!("{}", "-".repeat(widths.iter().sum::<usize>() + 2 * (cols - 1)));
    for r in rows {
        line(r.iter().map(|s| s.as_str()).collect());
    }
}

fn parse_info(input: &[u8], path: &Path) -> io::Result<()> {
    let lay = read_layout(input)?;
    let shdrs = &lay.shdrs;

    println!("=== RPL/RPX 解析結果 ===");
    println!("ファイル           : {}", path.display());
    println!("ファイルサイズ     : {} バイト (0x{:X})", input.len(), input.len());

    println!("\n[ELF ヘッダ]");
    println!(
        "  クラス           : {}",
        match input[4] {
            1 => "ELF32",
            2 => "ELF64",
            _ => "不明",
        }
    );
    println!(
        "  エンディアン     : {}",
        match input[5] {
            1 => "リトルエンディアン",
            2 => "ビッグエンディアン",
            _ => "不明",
        }
    );
    println!("  OS/ABI           : 0x{:02X}{}", input[7], if input[7] == 0xCA { " (Cafe OS)" } else { "" });
    println!(
        "  マシン           : 0x{:04X}{}",
        lay.machine,
        if lay.machine == 0x14 { " (PowerPC)" } else { "" }
    );
    println!("  エントリポイント : 0x{:08X}", lay.entry);
    println!("  プログラムヘッダ : 0x{:X}", lay.phoff);
    println!("  セクションヘッダ : 0x{:X} (数: {}, shstrndx: {})", lay.shoff, lay.shnum, lay.shstrndx);
    println!("  フラグ           : 0x{:08X}", lay.flags);

    // セクション名テーブル
    let strtab: Option<Vec<u8>> = shdrs
        .get(lay.shstrndx)
        .filter(|s| s.offset != 0)
        .and_then(|s| section_data(input, s).ok())
        .map(|c| c.into_owned());
    let name_of = |n: u32| -> String {
        strtab
            .as_ref()
            .and_then(|t| t.get(n as usize..))
            .map(|t| {
                let end = t.iter().position(|&b| b == 0).unwrap_or(t.len());
                String::from_utf8_lossy(&t[..end]).into_owned()
            })
            .unwrap_or_default()
    };

    // 保存されている CRC テーブル
    let stored_crcs: Option<&[u8]> = shdrs
        .iter()
        .find(|s| s.kind == SHT_RPL_CRCS && s.offset != 0)
        .and_then(|s| slice(input, s.offset as usize, s.size as usize).ok());

    let mut rows = Vec::new();
    let (mut total_stored, mut total_expanded) = (0u64, 0u64);
    let (mut zlib_count, mut data_count) = (0usize, 0usize);
    let (mut crc_ok, mut crc_ng) = (0usize, 0usize);

    for (i, sh) in shdrs.iter().enumerate() {
        let has_data = sh.offset != 0 && sh.kind != SHT_NOBITS;
        let mut expanded = "-".to_string();
        let mut crc_text = "-".to_string();

        if has_data {
            data_count += 1;
            total_stored += sh.size as u64;
            if sh.flags & SHF_RPL_ZLIB != 0 {
                zlib_count += 1;
            }
            match section_data(input, sh) {
                Ok(d) => {
                    expanded = d.len().to_string();
                    total_expanded += d.len() as u64;
                    if sh.kind != SHT_RPL_CRCS {
                        if let Some(t) = stored_crcs.filter(|t| t.len() >= (i + 1) * 4) {
                            let stored = u32::from_be_bytes(t[i * 4..i * 4 + 4].try_into().unwrap());
                            let calc = crc32_rpx(0, &d);
                            trace!("セクション #{i}: 保存CRC={stored:08X} 計算CRC={calc:08X}");
                            if stored == calc {
                                crc_ok += 1;
                                crc_text = format!("{calc:08X} 一致");
                            } else {
                                crc_ng += 1;
                                crc_text = format!("{stored:08X}≠{calc:08X} 不一致");
                            }
                        }
                    }
                }
                Err(e) => {
                    total_expanded += sh.size as u64;
                    expanded = format!("エラー({e})");
                    debug!("セクション #{i} の読み取りに失敗: {e}");
                }
            }
        }

        rows.push(vec![
            i.to_string(),
            name_of(sh.name),
            type_name(sh.kind),
            flag_str(sh.flags),
            format!("0x{:08X}", sh.addr),
            format!("0x{:X}", sh.offset),
            sh.size.to_string(),
            expanded,
            if sh.flags & SHF_RPL_ZLIB != 0 { "zlib".into() } else { "-".into() },
            crc_text,
        ]);
    }

    println!("\n[セクション一覧]");
    print_table(
        &[
            "番号", "名前", "種別", "フラグ", "アドレス", "オフセット", "格納サイズ", "展開後サイズ", "圧縮", "CRC",
        ],
        &rows,
    );
    println!("フラグ: W=書込可 A=メモリ確保 X=実行可 Z=zlib 圧縮");

    println!("\n[圧縮状態]");
    println!("  データを持つセクション数 : {data_count}");
    println!("  zlib 圧縮セクション数    : {zlib_count}");
    println!(
        "  状態                     : {}",
        if zlib_count == 0 {
            "未圧縮 (展開済み)"
        } else if zlib_count == data_count {
            "すべて圧縮済み"
        } else {
            "一部圧縮済み"
        }
    );
    if total_expanded > 0 {
        println!(
            "  格納サイズ合計           : {} バイト / 展開後 {} バイト ({:.1}%)",
            total_stored,
            total_expanded,
            total_stored as f64 * 100.0 / total_expanded as f64
        );
    }
    if stored_crcs.is_some() {
        println!("  CRC 検証                 : 一致 {crc_ok} / 不一致 {crc_ng}");
    } else {
        println!("  CRC 検証                 : CRC セクションが見つかりません");
    }

    // RPL_FILEINFO の詳細
    if let Some(fi) = shdrs.iter().find(|s| s.kind == SHT_RPL_FILEINFO && s.offset != 0) {
        if let Ok(d) = section_data(input, fi) {
            if d.len() >= 92 && be32(&d, 0)? == 0xCAFE_0402 {
                let g = |o: usize| be32(&d, o).unwrap_or(0);
                println!("\n[RPL ファイル情報]");
                println!("  バージョン       : 0x{:08X}", g(4));
                println!("  text サイズ      : 0x{:X} (アライン 0x{:X})", g(8), g(12));
                println!("  data サイズ      : 0x{:X} (アライン 0x{:X})", g(16), g(20));
                println!("  load サイズ      : 0x{:X} (アライン 0x{:X})", g(24), g(28));
                println!("  temp サイズ      : 0x{:X}", g(32));
                println!("  スタックサイズ   : 0x{:X}", g(48));
                println!("  ヒープサイズ     : 0x{:X}", g(60));
                println!("  最小バージョン   : 0x{:X}", g(68));
                println!("  圧縮レベル       : {}", g(72) as i32);
                println!("  Cafe SDK         : {}.{}", g(84), g(88));
            }
        }
    }

    Ok(())
}

// ───────────────────────── main ─────────────────────────

/// -i/--input (オプション) と位置引数の両方が指定された場合はエラー
fn merge_path(opt: Option<PathBuf>, pos: Option<PathBuf>, what: &str) -> Result<Option<PathBuf>, String> {
    match (opt, pos) {
        (Some(_), Some(_)) => Err(format!(
            "{what}がオプションと位置引数の両方で指定されています。どちらか一方にしてください"
        )),
        (a, b) => Ok(a.or(b)),
    }
}

fn fail(msg: &str) -> ExitCode {
    eprintln!("エラー: {msg}");
    ExitCode::FAILURE
}

fn main() -> ExitCode {

    println!("[プログラムの保存先]:\t{}\n", env::current_exe().unwrap_or_default().display());

    let name: &str = env!("CARGO_PKG_NAME");
    let version: &str = env!("CARGO_PKG_VERSION");
    let authors: &str = env!("CARGO_PKG_AUTHORS");
    let description: &str = env!("CARGO_PKG_DESCRIPTION");

    println!("\n\t=== 3DS {} (Rust版 v{}) ===", name, version);
    println!("\t{}\n\t{}\n", authors, description);

    let args = Args::parse();
    
    stderrlog::new()
        .module(module_path!())
        .quiet(args.quiet)
        .verbosity(2 + args.verbose as usize)
        .init()
        .expect("ロガーの初期化に失敗しました");


    // サブコマンドごとに (モード, 入力位置引数, 出力位置引数) を取り出す
    let (mode, in_pos, out_pos) = match args.command {
        Cmd::Compress { input_pos, output_pos } => (Some(Mode::Compress), input_pos, output_pos),
        Cmd::Decompress { input_pos, output_pos } => (Some(Mode::Decompress), input_pos, output_pos),
        Cmd::Parse { path } => (None, path, None),
    };

    let input_path = match merge_path(args.input, in_pos, "入力ファイル") {
        Ok(Some(p)) => p,
        Ok(None) => return fail("入力ファイルが指定されていません (-i/--input または位置引数で指定してください)"),
        Err(e) => return fail(&e),
    };
    let output_path = match merge_path(args.output, out_pos, "出力ファイル") {
        Ok(p) => p,
        Err(e) => return fail(&e),
    };

    debug!("入力: {}", input_path.display());

    let input = match fs::read(&input_path) {
        Ok(d) => d,
        Err(e) => return fail(&format!("入力ファイルを開けません '{}': {e}", input_path.display())),
    };
    debug!("読み込みサイズ: {} バイト", input.len());

    // parse
    let Some(mode) = mode else {
        if output_path.is_some() {
            return fail("parse では出力ファイルを指定できません");
        }
        return match parse_info(&input, &input_path) {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => fail(&e.to_string()),
        };
    };

    info!(
        "{}を開始します: {}",
        if mode == Mode::Decompress { "展開" } else { "圧縮" },
        input_path.display()
    );

    let output = match process(&input, mode) {
        Ok(o) => o,
        Err(e) => return fail(&e.to_string()),
    };

    // 入力は全てメモリに読み込み済みなので、同じパスへの上書きも安全
    let out_path = output_path.unwrap_or(input_path);
    debug!("出力先: {} ({} バイト)", out_path.display(), output.len());
    if let Err(e) = fs::write(&out_path, &output) {
        return fail(&format!("出力ファイルを書き込めません '{}': {e}", out_path.display()));
    }

    info!(
        "完了: {} ({} → {} バイト)",
        out_path.display(),
        input.len(),
        output.len()
    );
    ExitCode::SUCCESS
}
