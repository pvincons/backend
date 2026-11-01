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
const { PDFDocument, PDFName, PDFNumber, PDFArray, PDFDict, PDFRef } = require('pdf-lib');

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
// PHA 1: chuẩn bị PDF có vùng chữ ký
// ---------------------------------------------------------------------------
/**
 * @param {Buffer} pdfBuffer
 * @param {{signingTime: Date, name?: string, reason?: string, location?: string, contactInfo?: string}} opts
 * @returns {Promise<{prepared: Buffer, digest: Buffer, contentsStart: number, byteRange: number[]}>}
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

    // Trang 1: thêm widget vào /Annots
    const page = doc.getPage(0);
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
        '<<\n/Type /Annot\n/Subtype /Widget\n/FT /Sig\n/Rect [0 0 0 0]\n/F 132\n' +
        '/T ' + pdfText(sigName) + '\n/V ' + sigRef.toString() + '\n/P ' + page.ref.toString() + '\n>>';

    const objs = [
        { num: sigNum, gen: 0, body: sigDict },
        { num: fieldNum, gen: 0, body: widgetDict },
        { num: page.ref.objectNumber, gen: page.ref.generationNumber, body: page.node.toString() },
        { num: info.Root.objectNumber, gen: info.Root.generationNumber, body: newCatalog.toString() }
    ];

    // Ghi phần cập nhật tăng dần
    const parts = [];
    let off = base.length;
    const push = (s) => { const b = Buffer.isBuffer(s) ? s : Buffer.from(s, 'latin1'); parts.push(b); off += b.length; };
    const last = base[base.length - 1];
    if (last !== 0x0a && last !== 0x0d) push('\n');
    const offsets = [];
    for (const o of objs) {
        offsets.push({ num: o.num, gen: o.gen, off });
        push(`${o.num} ${o.gen} obj\n${o.body}\nendobj\n`);
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
        'trailer\n<< /Size ' + (size + 2) +
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
    return { prepared, digest, contentsStart: lt + 1, byteRange };
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
