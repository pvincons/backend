'use strict';
/**
 * smartca-pdf-sign.js
 * Nhúng chữ ký số từ xa (VNPT SmartCA - signhash) vào chính file PDF.
 *
 * Quy trình 2 pha (vì khóa ký nằm trên máy chủ VNPT, ta chỉ gửi HASH đi ký):
 *   PHA 1 (khi gửi yêu cầu ký):
 *     1. preparePdf()          : thêm vào PDF 1 trường chữ ký + vùng /Contents trống (cập nhật tăng dần,
 *                                không làm hỏng các chữ ký đã có) và tính SHA-256 của phần PDF được ký (ByteRange).
 *     2. buildSignedAttrs()    : dựng "signed attributes" CMS (contentType, signingTime, messageDigest, ...).
 *     3. Gửi SHA-256( signedAttrs.toSign ) lên VNPT SmartCA /csc/signature/signhash.
 *   PHA 2 (khi gettraninfo trả tranStatus = 1):
 *     4. decodeSignature() + verifyRsaSignature() : lấy documents[0].sig, KIỂM TRA lại bằng khóa công khai
 *                                trong chứng thư trước khi nhúng (tránh nhúng chữ ký sai làm hỏng file).
 *     5. buildCms()            : đóng gói PKCS#7 / CMS (detached) kèm chuỗi chứng thư.
 *     6. embedCms()            : ghi PKCS#7 (hex) vào vùng /Contents.
 *
 * Chỉ phụ thuộc: crypto (có sẵn trong Node) và pdf-lib (đọc cấu trúc PDF).
 */
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const zlib = require('zlib');
const { PDFDocument, PDFName, PDFNumber, PDFArray, PDFDict, PDFRef, StandardFonts } = require('pdf-lib');

// Kích thước vùng chứa chữ ký (byte). PKCS#7 gồm chuỗi chứng thư ~5-7KB; để dư cho chuỗi dài hơn.
const SIGNATURE_BYTES = 16384;
const SIGNATURE_HEX_LEN = SIGNATURE_BYTES * 2;
const BYTERANGE_PLACEHOLDER = '/ByteRange [0 ********** ********** **********]';

const OID = {
    data: '1.2.840.113549.1.7.1',
    signedData: '1.2.840.113549.1.7.2',
    contentType: '1.2.840.113549.1.9.3',
    messageDigest: '1.2.840.113549.1.9.4',
    signingTime: '1.2.840.113549.1.9.5',
    signingCertificateV2: '1.2.840.113549.1.9.16.2.47',
    sha256: '2.16.840.1.101.3.4.2.1',
    rsaEncryption: '1.2.840.113549.1.1.1'
};

const sha256 = (buf) => crypto.createHash('sha256').update(buf).digest();

// ---------------------------------------------------------------------------
// DER (ASN.1) tối giản
// ---------------------------------------------------------------------------
function derLen(n) {
    if (n < 128) return Buffer.from([n]);
    const bytes = [];
    while (n > 0) { bytes.unshift(n & 255); n = Math.floor(n / 256); }
    return Buffer.from([0x80 | bytes.length, ...bytes]);
}
function tlv(tag, ...parts) {
    const body = Buffer.concat(parts);
    return Buffer.concat([Buffer.from([tag]), derLen(body.length), body]);
}
const seq = (...p) => tlv(0x30, ...p);
const set = (...p) => tlv(0x31, ...p);
const octets = (b) => tlv(0x04, b);
const nul = () => Buffer.from([0x05, 0x00]);
const derInt = (n) => tlv(0x02, Buffer.from([n]));
function oid(str) {
    const a = str.split('.').map(Number);
    const bytes = [a[0] * 40 + a[1]];
    for (const v of a.slice(2)) {
        const t = [v & 127];
        let x = Math.floor(v / 128);
        while (x > 0) { t.unshift((x & 127) | 128); x = Math.floor(x / 128); }
        bytes.push(...t);
    }
    return tlv(0x06, Buffer.from(bytes));
}
function utcTime(d) {
    const p = (n) => String(n).padStart(2, '0');
    const s = p(d.getUTCFullYear() % 100) + p(d.getUTCMonth() + 1) + p(d.getUTCDate()) +
        p(d.getUTCHours()) + p(d.getUTCMinutes()) + p(d.getUTCSeconds()) + 'Z';
    return tlv(0x17, Buffer.from(s, 'ascii'));
}
function readTlv(buf, pos) {
    const tag = buf[pos];
    let len = buf[pos + 1];
    let hl = 2;
    if (len & 0x80) {
        const n = len & 0x7f;
        len = 0;
        for (let i = 0; i < n; i++) len = len * 256 + buf[pos + 2 + i];
        hl = 2 + n;
    }
    return { tag, hl, len, start: pos, end: pos + hl + len };
}

/** Lấy nguyên văn DER của Issuer và SerialNumber trong chứng thư X.509 (dùng cho SignerInfo). */
function certIssuerAndSerial(certDer) {
    const cert = readTlv(certDer, 0);
    const tbs = readTlv(certDer, cert.start + cert.hl);
    let p = tbs.start + tbs.hl;
    let t = readTlv(certDer, p);
    if (t.tag === 0xA0) { p = t.end; t = readTlv(certDer, p); } // bỏ [0] version
    const serialDer = certDer.subarray(t.start, t.end);
    p = t.end;
    const sigAlg = readTlv(certDer, p);
    p = sigAlg.end;
    const issuer = readTlv(certDer, p);
    return { serialDer, issuerDer: certDer.subarray(issuer.start, issuer.end) };
}

// ---------------------------------------------------------------------------
// Chứng thư
// ---------------------------------------------------------------------------
function b64ToDer(b64) { return Buffer.from(String(b64).replace(/\s+/g, ''), 'base64'); }

/** Chọn chứng thư của người ký trong chuỗi (khớp serialNumber từ credentials/info; mặc định phần tử đầu). */
function pickLeafCert(chainDer, serialHex) {
    const norm = (s) => String(s || '').replace(/^0+/, '').toLowerCase();
    if (serialHex) {
        for (const der of chainDer) {
            try {
                if (norm(new crypto.X509Certificate(der).serialNumber) === norm(serialHex)) return der;
            } catch (e) { /* bỏ qua */ }
        }
    }
    return chainDer[0];
}

function certSubjectCN(certDer) {
    try {
        const subject = new crypto.X509Certificate(certDer).subject || '';
        const m = subject.match(/^CN=(.*)$/m);
        return m ? m[1].trim() : '';
    } catch (e) { return ''; }
}

// ---------------------------------------------------------------------------
// Chuỗi PDF
// ---------------------------------------------------------------------------
function pdfText(s) {
    s = String(s == null ? '' : s);
    if (/^[\x20-\x7e]*$/.test(s)) return '(' + s.replace(/([\\()])/g, '\\$1') + ')';
    const be = Buffer.from('\uFEFF' + s, 'utf16le').swap16(); // UTF-16BE kèm BOM
    return '<' + be.toString('hex').toUpperCase() + '>';
}
function pdfDate(d) {
    const p = (n) => String(n).padStart(2, '0');
    return `(D:${d.getUTCFullYear()}${p(d.getUTCMonth() + 1)}${p(d.getUTCDate())}${p(d.getUTCHours())}${p(d.getUTCMinutes())}${p(d.getUTCSeconds())}Z)`;
}

function lastStartXref(buf) {
    const idx = buf.lastIndexOf('startxref');
    if (idx < 0) throw new Error('PDF không hợp lệ (thiếu startxref).');
    const m = buf.subarray(idx + 9, idx + 60).toString('latin1').match(/\s*(\d+)/);
    if (!m) throw new Error('PDF không hợp lệ (startxref sai định dạng).');
    return Number(m[1]);
}
const isClassicXref = (buf, off) => buf.subarray(off, off + 24).toString('latin1').trimStart().startsWith('xref');

// ---------------------------------------------------------------------------
// Con dấu chữ ký hiển thị (có tiếng Việt)
// Nhúng TẬP CON font TrueType (chỉ các glyph được dùng, ~20-40KB) bằng mã thuần Node, không cần thư viện font.
// Không tìm được font -> dùng Helvetica và bỏ dấu tiếng Việt.
// ---------------------------------------------------------------------------
const fontCache = new Map();

function findStampFontPath(custom) {
    const candidates = [
        custom,
        'C:\\Windows\\Fonts\\arial.ttf',
        'C:\\Windows\\Fonts\\tahoma.ttf',
        '/System/Library/Fonts/Supplemental/Arial.ttf',
        '/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf',
        '/usr/share/fonts/truetype/liberation/LiberationSans-Regular.ttf'
    ].filter(Boolean);
    return candidates.find((p) => { try { return fs.statSync(p).isFile(); } catch (e) { return false; } });
}

function parseTtf(buf) {
    const u16 = (o) => buf.readUInt16BE(o);
    const i16 = (o) => buf.readInt16BE(o);
    const u32 = (o) => buf.readUInt32BE(o);
    if (!(u32(0) === 0x00010000 || buf.toString('latin1', 0, 4) === 'true')) {
        throw new Error('font không phải TrueType (.ttf); .otf/.ttc chưa được hỗ trợ');
    }
    const tables = {};
    for (let i = 0, n = u16(4); i < n; i++) {
        const o = 12 + 16 * i;
        tables[buf.toString('latin1', o, o + 4)] = { off: u32(o + 8), len: u32(o + 12) };
    }
    for (const t of ['head', 'hhea', 'maxp', 'hmtx', 'loca', 'glyf', 'cmap']) {
        if (!tables[t]) throw new Error(`font thiếu bảng '${t}'`);
    }
    const os2 = tables['OS/2'];
    if (os2 && (u16(os2.off + 8) & 0x0002)) throw new Error('font cấm nhúng vào tài liệu (fsType)');

    const head = tables.head.off;
    const unitsPerEm = u16(head + 18);
    const locaFmt = i16(head + 50);
    const numGlyphs = u16(tables.maxp.off + 4);
    const nHM = u16(tables.hhea.off + 34);

    // cmap Unicode: ưu tiên format 12, rồi format 4
    const cm = tables.cmap.off;
    let best = null;
    for (let i = 0, n = u16(cm + 2); i < n; i++) {
        const plat = u16(cm + 4 + 8 * i), enc = u16(cm + 6 + 8 * i), off = cm + u32(cm + 8 + 8 * i);
        const fmt = u16(off);
        const isUnicode = (plat === 3 && (enc === 1 || enc === 10)) || plat === 0;
        if (!isUnicode || (fmt !== 4 && fmt !== 12)) continue;
        const rank = fmt === 12 ? 2 : 1;
        if (!best || rank > best.rank) best = { off, fmt, rank };
    }
    if (!best) throw new Error('font không có bảng cmap Unicode');
    const glyphId = (cp) => {
        if (best.fmt === 12) {
            for (let g = 0, nG = u32(best.off + 12); g < nG; g++) {
                const o = best.off + 16 + 12 * g;
                const s = u32(o), e = u32(o + 4);
                if (cp > e) continue;
                return cp < s ? 0 : u32(o + 8) + (cp - s);
            }
            return 0;
        }
        const segX2 = u16(best.off + 6);
        const endO = best.off + 14, startO = endO + segX2 + 2, deltaO = startO + segX2, rangeO = deltaO + segX2;
        for (let i = 0; i < segX2 / 2; i++) {
            if (cp > u16(endO + 2 * i)) continue;
            const st = u16(startO + 2 * i);
            if (cp < st) return 0;
            const ro = u16(rangeO + 2 * i), dl = u16(deltaO + 2 * i);
            if (ro === 0) return (cp + dl) & 0xFFFF;
            const g = u16(rangeO + 2 * i + ro + 2 * (cp - st));
            return g === 0 ? 0 : (g + dl) & 0xFFFF;
        }
        return 0;
    };
    const advance = (g) => u16(tables.hmtx.off + 4 * (g < nHM ? g : nHM - 1));

    const ascent = i16(tables.hhea.off + 4), descent = i16(tables.hhea.off + 6);
    const k = 1000 / unitsPerEm;
    return {
        buf, tables, unitsPerEm, locaFmt, numGlyphs, glyphId, advance,
        ascent: Math.round(ascent * k), descent: Math.round(descent * k),
        capHeight: (os2 && u16(os2.off) >= 2 && os2.len >= 90) ? Math.round(i16(os2.off + 88) * k) : Math.round(ascent * k * 0.72),
        bbox: [i16(head + 36), i16(head + 38), i16(head + 40), i16(head + 42)].map((v) => Math.round(v * k))
    };
}

function sfntChecksum(buf) {
    let s = 0;
    for (let i = 0; i < buf.length; i += 4) s = (s + buf.readUInt32BE(i)) >>> 0;
    return s;
}
function buildSfnt(tableMap) {
    const tags = Object.keys(tableMap).sort();
    const n = tags.length;
    let es = 0;
    while ((1 << (es + 1)) <= n) es++;
    const searchRange = (1 << es) * 16;
    const header = Buffer.alloc(12 + 16 * n);
    header.writeUInt32BE(0x00010000, 0);
    header.writeUInt16BE(n, 4);
    header.writeUInt16BE(searchRange, 6);
    header.writeUInt16BE(es, 8);
    header.writeUInt16BE(n * 16 - searchRange, 10);
    let off = header.length;
    const bodies = [];
    tags.forEach((t, i) => {
        const d = tableMap[t];
        const padded = Buffer.concat([d, Buffer.alloc((4 - (d.length % 4)) % 4)]);
        const o = 12 + 16 * i;
        header.write(t, o, 'latin1');
        header.writeUInt32BE(sfntChecksum(padded), o + 4);
        header.writeUInt32BE(off, o + 8);
        header.writeUInt32BE(d.length, o + 12);
        bodies.push(padded);
        off += padded.length;
    });
    return Buffer.concat([header, ...bodies]);
}

/** Tập con TrueType GIỮ NGUYÊN số hiệu glyph (nên dùng CIDToGIDMap /Identity): glyph không dùng được làm rỗng. */
function subsetTtf(font, usedGids) {
    const { buf, tables: T, numGlyphs } = font;
    const locaAt = (g) => font.locaFmt === 0 ? buf.readUInt16BE(T.loca.off + 2 * g) * 2 : buf.readUInt32BE(T.loca.off + 4 * g);
    const range = (g) => [T.glyf.off + locaAt(g), T.glyf.off + locaAt(g + 1)];
    const keep = new Set();
    const visit = (g) => {
        if (keep.has(g) || g >= numGlyphs) return;
        keep.add(g);
        const [s, e] = range(g);
        if (e - s >= 10 && buf.readInt16BE(s) < 0) { // glyph ghép (dấu tiếng Việt thường là glyph ghép)
            let p = s + 10, flags;
            do {
                flags = buf.readUInt16BE(p);
                visit(buf.readUInt16BE(p + 2));
                p += 4 + ((flags & 0x1) ? 4 : 2);
                if (flags & 0x8) p += 2; else if (flags & 0x40) p += 4; else if (flags & 0x80) p += 8;
            } while (flags & 0x20);
        }
    };
    visit(0);
    usedGids.forEach(visit);

    const chunks = [];
    const loca = Buffer.alloc(4 * (numGlyphs + 1));
    let pos = 0;
    for (let g = 0; g < numGlyphs; g++) {
        loca.writeUInt32BE(pos, 4 * g);
        if (!keep.has(g)) continue;
        const [s, e] = range(g);
        const d = buf.subarray(s, e);
        const pad = (4 - (d.length % 4)) % 4;
        chunks.push(d, Buffer.alloc(pad));
        pos += d.length + pad;
    }
    loca.writeUInt32BE(pos, 4 * numGlyphs);

    const slice = (t) => Buffer.from(buf.subarray(T[t].off, T[t].off + T[t].len));
    const head = slice('head');
    head.writeUInt32BE(0, 8);   // checkSumAdjustment
    head.writeInt16BE(1, 50);   // loca dạng dài
    const out = { head, hhea: slice('hhea'), maxp: slice('maxp'), hmtx: slice('hmtx'), loca, glyf: Buffer.concat(chunks) };
    for (const t of ['cvt ', 'fpgm', 'prep']) if (T[t]) out[t] = slice(t);
    return buildSfnt(out);
}

const utf16beHex = (str) => Buffer.from(str, 'utf16le').swap16().toString('hex');
function streamObj(dictBody, data) {
    return Buffer.concat([
        Buffer.from(`<<\n${dictBody}\n/Length ${data.length}\n>>\nstream\n`, 'latin1'),
        data,
        Buffer.from('\nendstream', 'latin1')
    ]);
}

/** Engine chữ: font TrueType nhúng dạng CID (Identity-H) + ToUnicode (copy/tìm kiếm được tiếng Việt). */
function makeCidEngine(font, text) {
    const map = new Map();
    for (const ch of new Set([...text])) { const cp = ch.codePointAt(0); map.set(cp, font.glyphId(cp)); }
    const gids = [...new Set(map.values())].filter((g) => g > 0).sort((a, b) => a - b);
    const gidOf = (ch) => map.has(ch.codePointAt(0)) ? map.get(ch.codePointAt(0)) : font.glyphId(ch.codePointAt(0));
    return {
        objCount: 5,
        measure: (t, size) => { let w = 0; for (const ch of t) w += font.advance(gidOf(ch)); return w * size / font.unitsPerEm; },
        show: (t) => '<' + [...t].map((ch) => gidOf(ch).toString(16).padStart(4, '0')).join('') + '>',
        objects(first) {
            const sub = subsetTtf(font, gids);
            const hash = crypto.createHash('sha256').update(gids.join(',')).digest();
            const tag = [...hash.subarray(0, 6)].map((b) => String.fromCharCode(65 + (b % 26))).join('');
            const baseFont = `${tag}+PVIStamp`;
            const w1000 = (g) => Math.round(font.advance(g) * 1000 / font.unitsPerEm);
            const uni = new Map();
            for (const [cp, g] of map) if (g > 0 && !uni.has(g)) uni.set(g, cp);
            const bfchar = [...uni].map(([g, cp]) => `<${g.toString(16).padStart(4, '0')}> <${utf16beHex(String.fromCodePoint(cp))}>`).join('\n');
            const cmap = '/CIDInit /ProcSet findresource begin\n12 dict begin\nbegincmap\n' +
                '/CIDSystemInfo << /Registry (Adobe) /Ordering (UCS) /Supplement 0 >> def\n' +
                '/CMapName /Adobe-Identity-UCS def\n/CMapType 2 def\n' +
                '1 begincodespacerange\n<0000> <FFFF>\nendcodespacerange\n' +
                `${uni.size} beginbfchar\n${bfchar}\nendbfchar\nendcmap\nCMapName currentdict /CMap defineresource pop\nend\nend`;
            const L = (s) => Buffer.from(s, 'latin1');
            return {
                fontNum: first + 4,
                objs: [
                    { num: first, body: streamObj(`/Filter /FlateDecode\n/Length1 ${sub.length}`, zlib.deflateSync(sub)) },
                    { num: first + 1, body: L(`<<\n/Type /FontDescriptor\n/FontName /${baseFont}\n/Flags 32\n/FontBBox [${font.bbox.join(' ')}]\n/ItalicAngle 0\n/Ascent ${font.ascent}\n/Descent ${font.descent}\n/CapHeight ${font.capHeight}\n/StemV 80\n/FontFile2 ${first} 0 R\n>>`) },
                    { num: first + 2, body: L(`<<\n/Type /Font\n/Subtype /CIDFontType2\n/BaseFont /${baseFont}\n/CIDSystemInfo << /Registry (Adobe) /Ordering (Identity) /Supplement 0 >>\n/FontDescriptor ${first + 1} 0 R\n/DW 1000\n/W [${gids.map((g) => `${g} [${w1000(g)}]`).join(' ')}]\n/CIDToGIDMap /Identity\n>>`) },
                    { num: first + 3, body: streamObj('', L(cmap)) },
                    { num: first + 4, body: L(`<<\n/Type /Font\n/Subtype /Type0\n/BaseFont /${baseFont}\n/Encoding /Identity-H\n/DescendantFonts [${first + 2} 0 R]\n/ToUnicode ${first + 3} 0 R\n>>`) }
                ]
            };
        }
    };
}

/** Dự phòng khi không có font TrueType: Helvetica chuẩn, bỏ dấu tiếng Việt. */
async function makeHelveticaEngine() {
    const tmp = await PDFDocument.create();
    const f = await tmp.embedFont(StandardFonts.Helvetica);
    const fold = (t) => String(t).normalize('NFD').replace(/[\u0300-\u036f]/g, '').replace(/đ/g, 'd').replace(/Đ/g, 'D').replace(/[^\x20-\x7e]/g, '?');
    return {
        objCount: 1,
        measure: (t, size) => f.widthOfTextAtSize(fold(t), size),
        show: (t) => '(' + fold(t).replace(/([\\()])/g, '\\$1') + ')',
        objects: (first) => ({ fontNum: first, objs: [{ num: first, body: Buffer.from('<<\n/Type /Font\n/Subtype /Type1\n/BaseFont /Helvetica\n/Encoding /WinAnsiEncoding\n>>', 'latin1') }] })
    };
}

async function makeTextEngine(text, fontPath) {
    const p = findStampFontPath(fontPath);
    if (p) {
        try {
            let f = fontCache.get(p);
            if (!f) { f = parseTtf(fs.readFileSync(p)); fontCache.set(p, f); }
            return { engine: makeCidEngine(f, text), fontName: path.basename(p) };
        } catch (e) {
            console.warn(`[smartca-pdf-sign] Không dùng được font con dấu "${p}": ${e.message}`);
        }
    } else {
        console.warn('[smartca-pdf-sign] Không tìm thấy font TrueType cho con dấu (đặt SIGNATURE_FONT_PATH=đường dẫn .ttf).');
    }
    console.warn('[smartca-pdf-sign] Con dấu dùng Helvetica nên sẽ bị mất dấu tiếng Việt.');
    return { engine: await makeHelveticaEngine(), fontName: 'Helvetica' };
}

function fmtVnTime(d) {
    const t = new Date(d.getTime() + 7 * 3600 * 1000);
    const p = (n) => String(n).padStart(2, '0');
    return `${p(t.getUTCDate())}/${p(t.getUTCMonth() + 1)}/${t.getUTCFullYear()} ${p(t.getUTCHours())}:${p(t.getUTCMinutes())}:${p(t.getUTCSeconds())} (UTC+7)`;
}

/**
 * Bố cục con dấu trên trang (tọa độ HIỂN THỊ, góc dưới-phải, nhiều chữ ký xếp chồng lên trên, hết chỗ thì sang cột bên trái).
 * Tự co theo khổ giấy (bản vẽ A1 vẫn đọc được) và xoay đúng theo /Rotate của trang.
 */
function layoutStamp(engine, { lines, box, rotation, index }) {
    const rot = ((Math.round(rotation / 90) * 90) % 360 + 360) % 360;
    const W = box.width, H = box.height;
    const dispW = rot % 180 ? H : W, dispH = rot % 180 ? W : H;
    const s = Math.min(6, Math.max(0.8, Math.min(dispW, dispH) / 595));
    const f = (n) => String(Math.round(n * 100) / 100);
    const pad = 6 * s, w = 215 * s;
    const avail = w - 2 * pad;

    const specs = [
        { t: lines.title, size: 6.5 * s, color: '0.10 0.35 0.70' },
        { t: lines.name, size: 9.5 * s, color: '0.05 0.05 0.05' },
        { t: lines.time, size: 8 * s, color: '0.15 0.15 0.15' },
        lines.serial ? { t: lines.serial, size: 7 * s, color: '0.40 0.40 0.40' } : null
    ].filter(Boolean);
    // Chiều cao ô cố định theo cỡ chữ chuẩn (tên dài chỉ co chữ trong ô, không làm ô thấp đi -> các con dấu xếp đều nhau)
    specs.forEach((sp) => { sp.nominal = sp.size; });
    const h = 2 * pad + specs.reduce((a, sp) => a + sp.nominal * 1.3, 0);
    for (const sp of specs) {
        const minSize = sp.size * 0.75;
        while (engine.measure(sp.t, sp.size) > avail && sp.size > minSize) sp.size *= 0.97;
        if (engine.measure(sp.t, sp.size) > avail) {
            let t = sp.t;
            while (t.length > 1 && engine.measure(t + '…', sp.size) > avail) t = t.slice(0, -1);
            sp.t = t + '…';
        }
    }

    let c = `q\n0.97 0.98 1 rg\n0.10 0.35 0.70 RG\n${f(s)} w\n${f(s / 2)} ${f(s / 2)} ${f(w - s)} ${f(h - s)} re\nB\n`;
    let top = h - pad;
    for (const sp of specs) {
        c += `${sp.color} rg\nBT\n/F1 ${f(sp.size)} Tf\n${f(pad)} ${f(top - sp.nominal * 0.9)} Td\n${engine.show(sp.t)} Tj\nET\n`;
        top -= sp.nominal * 1.3;
    }
    c += 'Q\n';

    const m = 24 * s, gap = 6 * s;
    const rows = Math.max(1, Math.floor((dispH - 2 * m + gap) / (h + gap)));
    const col = Math.floor(index / rows), row = index % rows;
    let u = Math.max(m, dispW - m - w - col * (w + gap));
    if (u + w > dispW) u = Math.max(0, dispW - w);
    const v = m + row * (h + gap);

    // đổi sang tọa độ chưa xoay của trang + Matrix để con dấu luôn đứng thẳng khi hiển thị
    let rx, ry, rw, rh, matrix = null;
    if (rot === 0) { rx = u; ry = v; rw = w; rh = h; }
    else if (rot === 90) { rx = W - (v + h); ry = u; rw = h; rh = w; matrix = [0, 1, -1, 0, h, 0]; }
    else if (rot === 180) { rx = W - (u + w); ry = H - (v + h); rw = w; rh = h; matrix = [-1, 0, 0, -1, w, h]; }
    else { rx = v; ry = H - (u + w); rw = h; rh = w; matrix = [0, -1, 1, 0, 0, w]; }
    return {
        content: c,
        bbox: [0, 0, w, h].map(f),
        matrix: matrix && matrix.map(f),
        rect: [box.x + rx, box.y + ry, box.x + rx + rw, box.y + ry + rh].map(f)
    };
}

function countOccurrences(buf, needle) {
    let n = 0, i = 0;
    while ((i = buf.indexOf(needle, i)) >= 0) { n++; i += needle.length; }
    return n;
}

// ---------------------------------------------------------------------------
// PHA 1: chuẩn bị PDF có vùng chữ ký
// ---------------------------------------------------------------------------
/**
 * @param {Buffer} pdfBuffer
 * @param {{signingTime: Date, name?: string, reason?: string, location?: string, contactInfo?: string,
 *          stamp?: false | {serial?: string, fontPath?: string}}} opts
 *   stamp: con dấu chữ ký hiển thị trên trang đầu (mặc định bật; truyền false để ký ẩn)
 * @returns {Promise<{prepared: Buffer, digest: Buffer, contentsStart: number, byteRange: number[], stampFont?: string}>}
 */
async function preparePdf(pdfBuffer, opts) {
    const signingTime = opts.signingTime || new Date();
    let base = Buffer.from(pdfBuffer);
    const alreadySigned = base.includes('/ByteRange');

    let prevXref = lastStartXref(base);
    if (!isClassicXref(base, prevXref)) {
        // PDF dùng xref stream / object stream (PDF 1.5+): chuẩn hóa về xref dạng bảng.
        // Chỉ làm khi CHƯA có chữ ký nào, vì ghi lại toàn bộ file sẽ làm mất hiệu lực chữ ký cũ.
        if (alreadySigned) {
            throw new Error('PDF đã có chữ ký từ công cụ khác và dùng cấu trúc xref stream, chưa hỗ trợ ký nối tiếp.');
        }
        try {
            const tmp = await PDFDocument.load(base, { updateMetadata: false });
            base = Buffer.from(await tmp.save({ useObjectStreams: false }));
        } catch (e) {
            throw new Error('Không chuẩn hóa được PDF để ký: ' + e.message);
        }
        prevXref = lastStartXref(base);
        if (!isClassicXref(base, prevXref)) throw new Error('Không chuẩn hóa được cấu trúc xref của PDF.');
    }

    let doc;
    try {
        doc = await PDFDocument.load(base, { updateMetadata: false });
    } catch (e) {
        throw new Error('Không đọc được PDF (file hỏng hoặc đã mã hóa): ' + e.message);
    }
    const ctx = doc.context;
    const info = ctx.trailerInfo;
    if (info.Encrypt) throw new Error('PDF đã được mã hóa, không thể ký số.');
    if (!info.Root) throw new Error('PDF không hợp lệ (thiếu Root).');
    if (doc.getPageCount() < 1) throw new Error('PDF không có trang nào để gắn chữ ký.');

    // Số hiệu object mới phải lớn hơn mọi object hiện có
    const tail = base.subarray(prevXref).toString('latin1');
    const sizeMatch = tail.match(/\/Size\s+(\d+)/);
    const size = Math.max(ctx.largestObjectNumber + 1, sizeMatch ? Number(sizeMatch[1]) : 0);
    const sigNum = size;
    const fieldNum = size + 1;
    const sigRef = PDFRef.of(sigNum, 0);
    const fieldRef = PDFRef.of(fieldNum, 0);
    let next = size + 2;

    const page = doc.getPage(0);

    // Con dấu hiển thị: dựng trước khi cấp số hiệu object vì cần biết số object font
    let stamp = null, engine = null, stampFont;
    let apNum = 0, fontPack = null;
    if (opts.stamp !== false) {
        const so = opts.stamp || {};
        const lines = {
            title: 'CHỮ KÝ SỐ',
            name: 'Ký bởi: ' + (opts.name || ''),
            time: 'Ngày ký: ' + fmtVnTime(signingTime),
            serial: so.serial ? 'Số CTS: ' + String(so.serial).toUpperCase() : ''
        };
        const made = await makeTextEngine(Object.values(lines).join('') + '…', so.fontPath);
        engine = made.engine;
        stampFont = made.fontName;
        stamp = layoutStamp(engine, {
            lines,
            box: page.getCropBox(),
            rotation: page.getRotation().angle,
            index: countOccurrences(base, '/ByteRange') // số chữ ký đã có -> xếp con dấu mới vào vị trí kế tiếp
        });
        apNum = next++;
        fontPack = engine.objects(next);
        next += engine.objCount;
    }

    // Trang 1: thêm widget vào /Annots
    const annots = page.node.lookupMaybe(PDFName.of('Annots'), PDFArray);
    page.node.set(PDFName.of('Annots'), ctx.obj([...(annots ? annots.asArray() : []), fieldRef]));

    // Catalog: AcroForm.Fields += field, SigFlags = 3 (SignaturesExist | AppendOnly)
    const catalog = doc.catalog;
    const oldAcro = catalog.lookupMaybe(PDFName.of('AcroForm'), PDFDict);
    const acro = oldAcro ? oldAcro.clone() : ctx.obj({});
    const fields = acro.lookupMaybe(PDFName.of('Fields'), PDFArray);
    acro.set(PDFName.of('Fields'), ctx.obj([...(fields ? fields.asArray() : []), fieldRef]));
    acro.set(PDFName.of('SigFlags'), PDFNumber.of(3));
    const newCatalog = catalog.clone();
    newCatalog.set(PDFName.of('AcroForm'), acro);

    const sigName = 'Signature_' + Date.now().toString(36);
    const sigDict =
        '<<\n/Type /Sig\n/Filter /Adobe.PPKLite\n/SubFilter /adbe.pkcs7.detached\n' +
        BYTERANGE_PLACEHOLDER + '\n' +
        '/Contents <' + '0'.repeat(SIGNATURE_HEX_LEN) + '>\n' +
        '/M ' + pdfDate(signingTime) + '\n' +
        (opts.name ? '/Name ' + pdfText(opts.name) + '\n' : '') +
        (opts.reason ? '/Reason ' + pdfText(opts.reason) + '\n' : '') +
        (opts.location ? '/Location ' + pdfText(opts.location) + '\n' : '') +
        (opts.contactInfo ? '/ContactInfo ' + pdfText(opts.contactInfo) + '\n' : '') +
        '>>';
    const widgetDict =
        '<<\n/Type /Annot\n/Subtype /Widget\n/FT /Sig\n' +
        '/Rect [' + (stamp ? stamp.rect.join(' ') : '0 0 0 0') + ']\n/F 132\n' +
        (stamp ? '/AP << /N ' + apNum + ' 0 R >>\n' : '') +
        '/T ' + pdfText(sigName) + '\n/V ' + sigRef.toString() + '\n/P ' + page.ref.toString() + '\n>>';

    const objs = [
        { num: sigNum, gen: 0, body: sigDict },
        { num: fieldNum, gen: 0, body: widgetDict },
        { num: page.ref.objectNumber, gen: page.ref.generationNumber, body: page.node.toString() },
        { num: info.Root.objectNumber, gen: info.Root.generationNumber, body: newCatalog.toString() }
    ];
    if (stamp) {
        objs.push({
            num: apNum, gen: 0,
            body: streamObj(
                '/Type /XObject\n/Subtype /Form\n/BBox [' + stamp.bbox.join(' ') + ']\n' +
                (stamp.matrix ? '/Matrix [' + stamp.matrix.join(' ') + ']\n' : '') +
                '/Resources << /Font << /F1 ' + fontPack.fontNum + ' 0 R >> >>',
                Buffer.from(stamp.content, 'latin1'))
        });
        for (const o of fontPack.objs) objs.push({ num: o.num, gen: 0, body: o.body });
    }

    // Ghi phần cập nhật tăng dần
    const parts = [];
    let off = base.length;
    const push = (x) => { const b = Buffer.isBuffer(x) ? x : Buffer.from(x, 'latin1'); parts.push(b); off += b.length; };
    const last = base[base.length - 1];
    if (last !== 0x0a && last !== 0x0d) push('\n');
    const offsets = [];
    for (const o of objs) {
        offsets.push({ num: o.num, gen: o.gen, off });
        push(`${o.num} ${o.gen} obj\n`);
        push(o.body);
        push('\nendobj\n');
    }
    const xrefOff = off;
    offsets.sort((a, b) => a.num - b.num);
    push('xref\n');
    for (let i = 0; i < offsets.length;) {
        let j = i;
        while (j + 1 < offsets.length && offsets[j + 1].num === offsets[j].num + 1) j++;
        push(`${offsets[i].num} ${j - i + 1}\n`);
        for (let k = i; k <= j; k++) {
            push(`${String(offsets[k].off).padStart(10, '0')} ${String(offsets[k].gen).padStart(5, '0')} n \n`);
        }
        i = j + 1;
    }
    push(
        'trailer\n<< /Size ' + next +
        ' /Root ' + info.Root.toString() +
        (info.Info ? ' /Info ' + info.Info.toString() : '') +
        (info.ID ? ' /ID ' + info.ID.toString() : '') +
        ' /Prev ' + prevXref + ' >>\nstartxref\n' + xrefOff + '\n%%EOF\n'
    );
    const prepared = Buffer.concat([base, ...parts]);

    // Định vị vùng /Contents và /ByteRange trong phần mới thêm, rồi điền ByteRange thật
    const cIdx = prepared.indexOf('/Contents <', base.length, 'latin1');
    const brIdx = prepared.indexOf(BYTERANGE_PLACEHOLDER, base.length, 'latin1');
    if (cIdx < 0 || brIdx < 0) throw new Error('Không định vị được vùng chữ ký trong PDF.');
    const lt = cIdx + '/Contents '.length;            // vị trí dấu '<'
    const gt = lt + 1 + SIGNATURE_HEX_LEN;            // vị trí dấu '>'
    const byteRange = [0, lt, gt + 1, prepared.length - (gt + 1)];
    const inner = `0 ${byteRange[1]} ${byteRange[2]} ${byteRange[3]}`.padEnd(BYTERANGE_PLACEHOLDER.length - '/ByteRange []'.length, ' ');
    prepared.write('/ByteRange [' + inner + ']', brIdx, 'latin1');

    const digest = rangeDigest(prepared, byteRange);
    return { prepared, digest, contentsStart: lt + 1, byteRange, stampFont };
}

function rangeDigest(pdf, byteRange) {
    const h = crypto.createHash('sha256');
    h.update(pdf.subarray(byteRange[0], byteRange[0] + byteRange[1]));
    h.update(pdf.subarray(byteRange[2], byteRange[2] + byteRange[3]));
    return h.digest();
}

// ---------------------------------------------------------------------------
// Signed attributes + CMS
// ---------------------------------------------------------------------------
/**
 * @returns {{toSign: Buffer, implicit: Buffer}}
 *   toSign   : DER (thẻ SET 0x31) - đây là dữ liệu mà khóa ký phải ký -> băm SHA-256 rồi gửi VNPT signhash
 *   implicit : cùng nội dung nhưng thẻ [0] IMPLICIT (0xA0) - đặt vào SignerInfo
 */
function buildSignedAttrs({ contentDigest, certDer, signingTime }) {
    const attr = (o, v) => seq(oid(o), set(v));
    const attrs = [
        attr(OID.contentType, oid(OID.data)),
        attr(OID.signingTime, utcTime(signingTime)),
        attr(OID.messageDigest, octets(contentDigest)),
        // ESSCertIDv2 (SHA-256 là mặc định nên không ghi hashAlgorithm)
        attr(OID.signingCertificateV2, seq(seq(seq(octets(sha256(certDer))))))
    ].sort(Buffer.compare); // DER: SET OF phải sắp theo thứ tự byte
    const body = Buffer.concat(attrs);
    return { toSign: tlv(0x31, body), implicit: tlv(0xA0, body) };
}

function buildCms({ chainDer, signerCertDer, implicitAttrs, signature }) {
    const shaAlg = seq(oid(OID.sha256), nul());
    const { issuerDer, serialDer } = certIssuerAndSerial(signerCertDer);
    const signerInfo = seq(
        derInt(1),
        seq(issuerDer, serialDer),
        shaAlg,
        implicitAttrs,
        seq(oid(OID.rsaEncryption), nul()),
        octets(signature)
    );
    const signedData = seq(
        derInt(1),
        set(shaAlg),
        seq(oid(OID.data)),
        tlv(0xA0, ...chainDer),
        set(signerInfo)
    );
    return seq(oid(OID.signedData), tlv(0xA0, signedData));
}

// ---------------------------------------------------------------------------
// PHA 2: kiểm tra chữ ký VNPT trả về và nhúng vào PDF
// ---------------------------------------------------------------------------
/** documents[].sig của VNPT: chấp nhận base64 hoặc hex; độ dài đúng bằng modulus khóa RSA. */
function decodeSignature(sig, certDer) {
    const k = new crypto.X509Certificate(certDer).publicKey.asymmetricKeyDetails.modulusLength / 8;
    const s = String(sig || '').trim();
    if (/^[0-9a-fA-F]+$/.test(s) && s.length === k * 2) return Buffer.from(s, 'hex');
    const b = Buffer.from(s, 'base64');
    if (b.length === k) return b;
    throw new Error(`Chữ ký VNPT trả về có độ dài ${b.length} byte, không khớp khóa RSA ${k} byte (không phải chữ ký RSA thô).`);
}

function verifyRsaSignature(toSign, signature, certDer) {
    const key = new crypto.X509Certificate(certDer).publicKey;
    return crypto.verify('sha256', toSign, key, signature);
}

function embedCms(prepared, contentsStart, cms) {
    const hex = cms.toString('hex');
    if (hex.length > SIGNATURE_HEX_LEN) {
        throw new Error(`Chữ ký PKCS#7 (${cms.length} byte) vượt vùng dành sẵn (${SIGNATURE_BYTES} byte).`);
    }
    const region = prepared.subarray(contentsStart, contentsStart + SIGNATURE_HEX_LEN);
    if (region.toString('latin1') !== '0'.repeat(SIGNATURE_HEX_LEN)) {
        throw new Error('Vùng chữ ký trong PDF đã bị thay đổi.');
    }
    const out = Buffer.from(prepared);
    out.write(hex.padEnd(SIGNATURE_HEX_LEN, '0'), contentsStart, 'latin1');
    return out;
}

module.exports = {
    SIGNATURE_BYTES,
    sha256, b64ToDer, pickLeafCert, certSubjectCN,
    preparePdf, rangeDigest, buildSignedAttrs, buildCms,
    decodeSignature, verifyRsaSignature, embedCms
};
