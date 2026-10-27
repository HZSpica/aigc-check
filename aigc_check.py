#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
aigc_check.py —— 文件元数据隐式标识（AIGC 标识）检测器

依据:
  GB 45438-2025 《网络安全技术 人工智能生成合成内容标识方法》 第 6.1 条、附录 E
  TC260-PG-20252A  服务提供者编码规则
  TC260-PG-20259A  图片文件元数据隐式标识
  TC260-PG-20258A  文本文件元数据隐式标识
  TC260-PG-202510A 音频文件元数据隐式标识
  TC260-PG-20257A  视频文件元数据隐式标识
  TC260-PG-202511A 安全防护技术指南（SecurityData）
  TC260-PG-202512A 生成合成内容检测 第 1 部分：框架

设计原则:
  1. 只读、不改写被检文件；全部本地解析，不联网、不上传。
  2. 零第三方依赖，Python 3.8+ 标准库即可运行（便于在取证机 / 隔离环境使用）。
  3. 覆盖标准规定的全部原生嵌入位置，另加全文件关键字兜底扫描。
  4. 输出人读报告 + 机器可读 JSON（检测框架 7.5 f 条要求）。

用法:
  python aigc_check.py 样本.jpg
  python aigc_check.py 样本目录 -r
  python aigc_check.py 样本.mp4 --json
  python aigc_check.py 样本.docx --dump        # 附带全部元数据键，便于排查"标识被剥离"
"""

import argparse
import html
import json
import os
import re
import sys
import zipfile
import zlib

__version__ = "1.1.0"

NS_URI = "http://www.tc260.org.cn/ns/AIGC/1.0/"
FIELDS = [
    "Label", "ContentProducer", "ProduceID", "ReservedCode1",
    "ContentPropagator", "PropagateID", "ReservedCode2",
]
LABEL_DESC = {
    "1": "属于人工智能生成合成内容",
    "2": "可能为人工智能生成合成内容",
    "3": "疑似为人工智能生成合成内容",
}
OID_NAME = {
    "1.2.156.10197.1.401": "SM3 杂凑",
    "1.2.156.10197.1.401.1": "SM3 杂凑",
    "1.2.156.10197.1.501": "SM3withSM2 签名",
    "1.2.840.113549.1.1.11": "SHA-256 with RSA",
    "1.2.840.10045.4.3.2": "ECDSA with SHA-256",
    "1.3.14.3.2.26": "SHA-1",
}
# GB 45438-2025 附录 E j): 允许 0x21、0x23~0x5B、0x5D~0x7E 以及转义 \"
ALLOWED = set([0x21]) | set(range(0x23, 0x5C)) | set(range(0x5D, 0x7F))
CODE_RE = re.compile(r"^00([12])([1-4])([0-9A-Z]{18})([0-9A-Z]{5})$")


# --------------------------------------------------------------------------
# 基础工具
# --------------------------------------------------------------------------
class Hit:
    """一次标识命中记录。"""

    __slots__ = ("channel", "location", "raw", "note", "standard")

    def __init__(self, channel, location, raw, note="", standard=True):
        self.channel = channel      # 检出通道，如 "MP4 moov.udta.meta.ilst"
        self.location = location    # 文件内偏移 / 容器路径
        self.raw = raw              # 原始字符串
        self.note = note            # 备注（如"非标准键名""编码异常"）
        self.standard = standard    # 是否属于标准规定的位置

    def to_dict(self):
        return {
            "channel": self.channel, "location": self.location,
            "raw": self.raw[:4000], "note": self.note, "standard": self.standard,
        }


def decode_text(b, encodings=("utf-8", "gb18030", "latin-1")):
    if isinstance(b, str):
        return b
    for enc in encodings:
        try:
            return b.decode(enc)
        except (UnicodeDecodeError, LookupError):
            continue
    return b.decode("utf-8", "ignore")


def looks_like_label(text):
    return "AIGC" in text or "Label" in text


def json_objects(text, limit=64):
    """从任意文本中截取所有顶层 {...} 片段（字符串感知的括号配对）。"""
    out, i, n = [], 0, len(text)
    while i < n and len(out) < limit:
        j = text.find("{", i)
        if j < 0:
            break
        depth, k, instr, esc = 0, j, False, False
        while k < n:
            c = text[k]
            if instr:
                if esc:
                    esc = False
                elif c == "\\":
                    esc = True
                elif c == '"':
                    instr = False
            else:
                if c == '"':
                    instr = True
                elif c == "{":
                    depth += 1
                elif c == "}":
                    depth -= 1
                    if depth == 0:
                        break
            k += 1
        if k >= n:
            break
        out.append(text[j:k + 1])
        i = k + 1
    return out


def parse_ident(raw):
    """把命中原文解析成字段字典。

    返回 (fields_or_None, mode, notes)
      mode: "wrapped"  -> {"AIGC":{...}}（GB 45438 附录 E 外层格式）
            "inner"    -> {...}（TC260 各格式正文，容器键已是 AIGC）
            "partial"  -> JSON 解析失败，靠正则兜底抓到部分字段
    """
    notes = []
    if not raw:
        return None, None, ["空值"]
    # XMP/XML 序列化器常把 " 转成 &quot;、把 & 转成 &amp;（libxmp 等实现即如此），
    # 也有实现用 CDATA 包裹。先还原为普通 JSON 再解析。
    text = html.unescape(raw)
    for cdata in re.findall(r"<!\[CDATA\[(.*?)\]\]>", text, re.S):
        if looks_like_label(cdata):
            text += "\n" + cdata
    for cand in json_objects(text):
        if not looks_like_label(cand):
            continue
        for variant in (cand, cand.replace('\\"', '"'), cand.replace("\\\\", "\\")):
            try:
                obj = json.loads(variant)
            except Exception:
                continue
            if not isinstance(obj, dict):
                continue
            if "AIGC" in obj:
                inner = obj["AIGC"]
                if isinstance(inner, dict):
                    return inner, "wrapped", notes
                if isinstance(inner, str):
                    try:
                        inner = json.loads(inner.replace('\\"', '"'))
                        if isinstance(inner, dict):
                            return inner, "wrapped", notes
                    except Exception:
                        notes.append("AIGC 键的值不是合法 JSON")
            if "Label" in obj:
                return obj, "inner", notes
    # 正则兜底：JSON 被截断、被转义、被平台改写时仍尽量取证
    fields = {}
    for f in FIELDS:
        m = re.search(r'"?' + f + r'"?\s*[:=]\s*"([^"\\]*)"', text)
        if m:
            fields[f] = m.group(1)
    if fields:
        notes.append("JSON 结构不完整，仅按正则提取到部分字段")
        return fields, "partial", notes
    return None, None, ["无法解析出标识字段"]


def check_charset(value):
    """GB 45438-2025 附录 E j) 字符集校验（作用于解析后的字符串值）。

    标准允许的字符为 0x21、0x23~0x5B、0x5D~0x7E，以及作为转义序列的 \\"。
    解析后引号与反斜杠会还原成裸字符，故此处按"ASCII 可打印字符"判定：
    出现控制字符、中文或其他非 ASCII 字符即判为不合规。
    """
    bad = sorted({c for c in value if not (0x20 <= ord(c) <= 0x7E)})
    return bad


def decode_provider_code(code):
    """按 TC260-PG-20252A 拆解 27 位服务提供者编码。"""
    m = CODE_RE.match(code or "")
    if not m:
        return None
    gtype, bind, subject, ext = m.groups()
    out = {
        "format_code": "00（本指南 V1.0）",
        "subject_type": "组织" if gtype == "1" else "个人",
        "bind": {
            "1": "统一社会信用代码" if gtype == "1" else "公民身份号码",
            "2": "移动通信终端号码", "3": "护照号码", "4": "网号",
        }.get(bind, "未知"),
        "subject_code": subject.strip("0") or subject,
        "ext_raw": ext,
    }
    if ext == "00000":
        out["service_type"] = "服务扩展码未编写"
        out["model_code"] = "-"
    else:
        out["service_type"] = {"1": "生成合成服务", "2": "内容传播服务"}.get(ext[0], "未知")
        out["model_code"] = ext[1:]
    return out


def describe_provider_code(code):
    d = decode_provider_code(code)
    if not d:
        return None
    return "格式码{v} | {t} | 绑定{b} | 主体{id} | 服务{s}{m}".format(
        v=d["format_code"][:2], t=d["subject_type"], b=d["bind"],
        id=d["subject_code"], s=d["service_type"],
        m="" if d["model_code"] == "-" else "（模型/应用码 " + d["model_code"] + "）",
    )


def normalize_hex(s):
    return re.sub(r"\s+", "", s or "").upper()


# --------------------------------------------------------------------------
# XMP / EXIF 通用解析
# --------------------------------------------------------------------------
def xmp_hits(raw, loc):
    """从 XMP packet（bytes 或 str）中提取 TC260:AIGC。"""
    text = decode_text(raw)
    hits = []
    # 1) 元素形式 <TC260:AIGC>{...}</TC260:AIGC>
    for m in re.finditer(r"<([A-Za-z0-9_.\-]*:)?AIGC\b[^>]*>(.*?)</\1?AIGC\s*>",
                         text, re.S | re.I):
        hits.append(Hit("XMP 元素 " + (m.group(1) or "").rstrip(":") + "AIGC"
                        if m.group(1) else "XMP 元素 AIGC", loc, m.group(2).strip()))
    # 2) 属性形式 tc260:AIGC="..."
    for m in re.finditer(r'([A-Za-z0-9_.\-]+):AIGC\s*=\s*"([^"]*)"', text, re.I):
        if m.group(1).lower() in ("xmlns", "rdf"):
            continue
        hits.append(Hit("XMP 属性 %s:AIGC" % m.group(1), loc, m.group(2)))
    # 3) 只有命名空间声明 + 裸 JSON（部分实现写法不规范）
    if not hits and NS_URI in text:
        for obj in json_objects(text):
            if "Label" in obj:
                hits.append(Hit("XMP 命名空间 TC260（无标准元素）", loc, obj,
                                "存在 tc260 命名空间但未找到 AIGC 元素"))
                break
    return hits


def usercomment_hits(val, loc):
    """EXIF UserComment（TC260-PG-20259A 附录 B 允许的备选方案）。"""
    head = val[:8]
    if head.startswith(b"ASCII"):
        txt = decode_text(val[8:], ("ascii", "utf-8", "gb18030"))
    elif head.startswith(b"UNICODE"):
        body = val[8:]
        txt = ""
        for enc in ("utf-16-le", "utf-16-be"):
            try:
                t = body.decode(enc, "ignore")
            except Exception:
                continue
            if "AIGC" in t or "Label" in t:
                txt = t
                break
        if not txt:
            txt = body.decode("utf-16-le", "ignore")
    elif head.startswith(b"JIS"):
        txt = decode_text(val[8:], ("shift_jis", "utf-8"))
    else:
        txt = decode_text(val, ("utf-8", "gb18030"))
    txt = txt.replace("\x00", "")
    if "AIGC" in txt or "Label" in txt:
        return [Hit("EXIF UserComment（备选方案）", loc, txt)]
    return []


def tiff_ifd_hits(tiff, prefix):
    """解析 TIFF/EXIF IFD，取 0x2BC(XMLPacket) 与 0x9286(UserComment)。"""
    hits, meta = [], []
    if len(tiff) < 8:
        return hits, meta
    bo = "little" if tiff[:2] == b"II" else "big"

    def r16(o):
        return int.from_bytes(tiff[o:o + 2], bo)

    def r32(o):
        return int.from_bytes(tiff[o:o + 4], bo)

    ifd0 = r32(4) if len(tiff) >= 8 else 0
    tsize = {1: 1, 2: 1, 3: 2, 4: 4, 5: 8, 6: 1, 7: 1, 8: 2, 9: 4, 10: 8, 11: 4, 12: 8}
    pending, seen = [ifd0], set()
    ifd_no = 0
    while pending:
        off = pending.pop(0)
        if off in seen or off + 2 > len(tiff):
            continue
        seen.add(off)
        cnt = r16(off)
        for k in range(cnt):
            e = off + 2 + k * 12
            if e + 12 > len(tiff):
                break
            tag, typ, num = r16(e), r16(e + 2), r32(e + 4)
            total = tsize.get(typ, 1) * num
            start = e + 8 if total <= 4 else r32(e + 8)
            if total <= 0 or start + total > len(tiff):
                continue
            val = tiff[start:start + total]
            meta.append("IFD%d tag 0x%04X len=%d" % (ifd_no, tag, total))
            if tag == 0x2BC:
                hits += xmp_hits(val, "%s/IFD tag0x2BC" % prefix)
            elif tag == 0x9286:
                hits += usercomment_hits(val, "%s/IFD UserComment" % prefix)
            elif tag in (0x010E, 0x010F, 0x0110, 0x9C9D) and b"AIGC" in val:
                hits.append(Hit("EXIF 文本标签 0x%04X" % tag,
                                "%s/IFD" % prefix, decode_text(val),
                                "非标准位置，仅作线索"))
        nxt_pos = off + 2 + cnt * 12
        if nxt_pos + 4 <= len(tiff):
            nxt = r32(nxt_pos)
            if nxt:
                pending.append(nxt)
        ifd_no += 1
    return hits, meta


# --------------------------------------------------------------------------
# 图片
# --------------------------------------------------------------------------
def parse_jpeg(data):
    hits, meta = [], []
    if data[:2] != b"\xff\xd8":
        return hits, meta
    i, n = 2, len(data)
    names = {0xE0: "APP0", 0xE1: "APP1", 0xE2: "APP2", 0xED: "APP13", 0xEE: "APP14",
             0xFE: "COM", 0xDB: "DQT", 0xC0: "SOF0", 0xC4: "DHT"}
    while i + 4 <= n:
        if data[i] != 0xFF:
            i += 1
            continue
        while i + 1 < n and data[i] == 0xFF and data[i + 1] == 0xFF:
            i += 1
        marker = data[i + 1]
        if marker in (0xD8, 0x01) or 0xD0 <= marker <= 0xD7:
            i += 2
            continue
        if marker == 0xDA:      # SOS：之后是熵编码数据
            meta.append("SOS @0x%X" % i)
            break
        size = int.from_bytes(data[i + 2:i + 4], "big")
        if size < 2:
            break
        payload = data[i + 4:i + 2 + size]
        tag = names.get(marker, "0xFF%02X" % marker)
        meta.append("%s @0x%X len=%d" % (tag, i, size))
        if marker == 0xE1:
            if payload.startswith(b"http://ns.adobe.com/xap/1.0/\x00"):
                hits += xmp_hits(payload[29:], "APP1/XMP @0x%X" % i)
            elif payload.startswith(b"http://ns.adobe.com/xmp/extension/\x00"):
                hits += xmp_hits(payload[35:], "APP1/XMP扩展 @0x%X" % i)
            elif payload.startswith(b"Exif\x00\x00"):
                h, m = tiff_ifd_hits(payload[6:], "APP1/EXIF @0x%X" % i)
                hits += h
                meta += m
        elif marker == 0xFE:
            if b"AIGC" in payload:
                hits.append(Hit("JPEG 注释段 COM", "@0x%X" % i, decode_text(payload),
                                "非标准位置，仅作线索", standard=False))
        i += 2 + size
    return hits, meta


def png_text_hit(keyword, value_bytes, loc):
    text = decode_text(value_bytes)
    k = (keyword or "").upper()
    if "AIGC" in k:
        return [Hit("PNG 文本块（keyword=%s）" % keyword, loc, text)]
    if "AIGC" in text or '"Label"' in text:
        return [Hit("PNG 文本块（keyword=%s）" % keyword, loc, text,
                    "标识写在非 AIGC 键名下", standard=False)]
    return []


def parse_png(data):
    hits, meta = [], []
    if data[:8] != b"\x89PNG\r\n\x1a\n":
        return hits, meta
    i, n = 8, len(data)
    while i + 8 <= n:
        ln = int.from_bytes(data[i:i + 4], "big")
        typ = data[i + 4:i + 8]
        body = data[i + 8:i + 8 + ln]
        meta.append("%s @0x%X len=%d" % (typ.decode("latin-1"), i, ln))
        if typ == b"tEXt":
            k, _, v = body.partition(b"\x00")
            hits += png_text_hit(decode_text(k, ("latin-1",)), v, "chunk tEXt @0x%X" % i)
        elif typ == b"zTXt":
            k, _, rest = body.partition(b"\x00")
            try:
                v = zlib.decompress(rest[1:])
            except Exception:
                v = b""
            hits += png_text_hit(decode_text(k, ("latin-1",)), v, "chunk zTXt @0x%X" % i)
        elif typ == b"iTXt":
            k, _, rest = body.partition(b"\x00")
            comp_flag = rest[0] if rest else 0
            rest2 = rest[2:]
            _lang, _, rest3 = rest2.partition(b"\x00")
            _tkey, _, text = rest3.partition(b"\x00")
            if comp_flag:
                try:
                    text = zlib.decompress(text)
                except Exception:
                    pass
            if decode_text(k, ("latin-1",)).lower() == "xml:com.adobe.xmp":
                hits += xmp_hits(text, "chunk iTXt(XMP) @0x%X" % i)
            else:
                hits += png_text_hit(decode_text(k, ("latin-1",)), text,
                                     "chunk iTXt @0x%X" % i)
        elif typ == b"IEND":
            break
        i += 12 + ln
    return hits, meta


def riff_walk(data, start, end, hits, meta, path="", depth=0, info_only=False):
    """RIFF 容器通用遍历（WAV / AVI / WebP）。"""
    i = start
    while i + 8 <= end:
        cid = data[i:i + 4]
        ln = int.from_bytes(data[i + 4:i + 8], "little")
        body_start = i + 8
        body_end = min(body_start + ln, end)
        meta.append("%s%s len=%d @0x%X" % ("  " * depth, cid.decode("latin-1", "replace"),
                                           ln, i))
        if cid == b"LIST" and body_start + 4 <= body_end:
            sub = data[body_start:body_start + 4]
            meta.append("%sLIST/%s" % ("  " * depth, sub.decode("latin-1", "replace")))
            riff_walk(data, body_start + 4, body_end, hits, meta,
                      path + "LIST:" + sub.decode("latin-1", "replace") + ".", depth + 1)
        elif cid == b"AIGC":
            hits.append(Hit(path + "RIFF 块 AIGC", "@0x%X" % i,
                            decode_text(data[body_start:body_end])))
        elif cid == b"XMP ":
            hits += xmp_hits(data[body_start:body_end], path + "XMP chunk @0x%X" % i)
        i += 8 + ln + (ln & 1)
    return hits


def parse_riff(data, kind):
    hits, meta = [], []
    if data[:4] != b"RIFF" or len(data) < 12:
        return hits, meta
    form = data[8:12]
    meta.append("RIFF form=%s" % form.decode("latin-1", "replace"))
    riff_walk(data, 12, len(data), hits, meta, depth=0)
    return hits, meta


def parse_tiff_file(data):
    return tiff_ifd_hits(data, "TIFF")


# --------------------------------------------------------------------------
# ISO BMFF（MP4 / MOV / M4A / HEIC）：moov.udta.meta.{keys,ilst}
# --------------------------------------------------------------------------
def bmff_boxes(data, start, end):
    out, i = [], start
    while i + 8 <= end:
        size = int.from_bytes(data[i:i + 4], "big")
        typ = data[i + 4:i + 8]
        hdr = 8
        if size == 1:
            if i + 16 > end:
                break
            size = int.from_bytes(data[i + 8:i + 16], "big")
            hdr = 16
        elif size == 0:
            size = end - i
        if size < hdr or i + size > end:
            break
        out.append((typ, i, i + size, hdr))
        i += size
    return out


def bmff_meta_hits(data, s, e, hdr, loc, hits, meta):
    """解析 meta 下的 keys + ilst（mdta 体系，标准指定位置）。"""
    base = s + hdr + 4          # meta 是 FullBox，跳 4 字节 version/flags
    keys, ilst = [], None
    for typ, bs, be, bh in bmff_boxes(data, base, e):
        meta.append("%s.%s" % (loc, typ.decode("latin-1", "replace")))
        if typ == b"keys":
            body = data[bs + bh:be]
            cnt = int.from_bytes(body[4:8], "big") if len(body) >= 8 else 0
            p, idx = 8, 1
            while p + 8 <= len(body) and idx <= cnt:
                ksz = int.from_bytes(body[p:p + 4], "big")
                if ksz < 8 or p + ksz > len(body):
                    break
                keys.append(decode_text(body[p + 8:p + ksz]))
                p += ksz
                idx += 1
        elif typ == b"ilst":
            ilst = (bs + bh, be)
    if not ilst:
        return
    for typ, s2, e2, h2 in bmff_boxes(data, ilst[0], ilst[1]):
        idx = int.from_bytes(typ, "big") if typ != b"----" else 0
        name = keys[idx - 1] if 0 < idx <= len(keys) else (
            "----(freeform)" if typ == b"----" else "#%d" % idx)
        payloads = []
        if typ == b"----":
            fname = ""
            for t3, b3, e3, h3 in bmff_boxes(data, s2 + h2, e2):
                raw = data[b3 + h3:e3]
                if t3 == b"name":
                    fname = decode_text(raw[4:] if len(raw) > 4 else raw)
                elif t3 == b"data":
                    payloads.append(raw[8:] if len(raw) >= 8 else raw)
            if "AIGC" in fname.upper():
                for p in payloads:
                    hits.append(Hit("BMFF freeform 键 %s" % fname,
                                    "%s.ilst" % loc, decode_text(p)))
            continue
        for t3, b3, e3, h3 in bmff_boxes(data, s2 + h2, e2):
            if t3 == b"data":
                raw = data[b3 + h3:e3]
                payloads.append(raw[8:] if len(raw) >= 8 else raw)
        text = " ".join(decode_text(p) for p in payloads)
        if "AIGC" in name.upper():
            hits.append(Hit("BMFF meta 键 %s" % name, "%s.ilst" % loc, text))
        elif "AIGC" in text or '"Label"' in text:
            hits.append(Hit("BMFF meta 键 %s" % name, "%s.ilst" % loc, text,
                            "标识写在非 AIGC 键名下", standard=False))


def parse_bmff(data):
    hits, meta = [], []
    for typ, s, e, hdr in bmff_boxes(data, 0, len(data)):
        meta.append("%s @0x%X len=%d" % (typ.decode("latin-1", "replace"), s, e - s))
        if typ == b"moov":
            for t2, s2, e2, h2 in bmff_boxes(data, s + hdr, e):
                meta.append("  moov.%s" % t2.decode("latin-1", "replace"))
                if t2 == b"udta":
                    for t3, s3, e3, h3 in bmff_boxes(data, s2 + h2, e2):
                        tag = "moov.udta.%s" % t3.decode("latin-1", "replace")
                        meta.append("    " + tag)
                        if t3 == b"meta":
                            bmff_meta_hits(data, s3, e3, h3, tag, hits, meta)
                        elif t3 in (b"\xa9cmt", b"\xa9too", b"name"):
                            txt = decode_text(data[s3 + h3:e3])
                            if "AIGC" in txt:
                                hits.append(Hit("BMFF 文本 atom " + tag,
                                                "@0x%X" % s3, txt,
                                                "非标准位置，仅作线索",
                                                standard=False))
                elif t2 == b"meta":
                    bmff_meta_hits(data, s2, e2, h2, "moov.meta", hits, meta)
        elif typ == b"meta":
            # HEIF/HEIC 等：meta 位于顶层，不在 moov 内
            bmff_meta_hits(data, s, e, hdr, "meta", hits, meta)
    return hits, meta


# --------------------------------------------------------------------------
# 音频：WAV / MP3 / OGG / FLAC / M4A
# --------------------------------------------------------------------------
def parse_wav(data):
    return parse_riff(data, "wav")


def parse_mp3(data):
    """ID3v2 TXXX 帧，Description="AIGC"。"""
    hits, meta = [], []
    if data[:3] != b"ID3":
        return hits, meta
    ver = data[3]
    flags = data[5]
    size = 0
    for b in data[6:10]:
        size = (size << 7) | (b & 0x7F)
    meta.append("ID3v2.%d.%d size=%d" % (ver, data[4], size))
    i, end = 10, min(10 + size, len(data))
    if flags & 0x40:            # 扩展头
        i += 4 + int.from_bytes(data[10:14], "big")
    while i + 10 <= end:
        fid = data[i:i + 4]
        if not re.match(rb"^[A-Z0-9]{4}$", fid):
            break
        raw_size = int.from_bytes(data[i + 4:i + 8], "big")
        fsize = raw_size if ver < 4 else (
            ((raw_size >> 24) & 0x7F) << 21 | ((raw_size >> 16) & 0x7F) << 14 |
            ((raw_size >> 8) & 0x7F) << 7 | (raw_size & 0x7F))
        if fsize <= 0 or i + 10 + fsize > end:
            break
        body = data[i + 10:i + 10 + fsize]
        meta.append("frame %s size=%d" % (fid.decode("latin-1"), fsize))
        if fid in (b"TXXX", b"TXX"):
            enc = body[0] if body else 0
            rest = body[1:]
            cod = {0: "latin-1", 1: "utf-16", 2: "utf-16-be", 3: "utf-8"}.get(enc, "latin-1")
            if enc in (1, 2):
                # UTF-16：终止符是两个 0x00，且必须落在偶数边界上
                k2 = 0
                while k2 + 1 < len(rest):
                    if rest[k2] == 0 and rest[k2 + 1] == 0:
                        break
                    k2 += 2
                desc_b, val_b = rest[:k2], rest[k2 + 2:]
                desc = decode_text(desc_b, (cod, "utf-16-le"))
                val = decode_text(val_b, (cod, "utf-16-le", "utf-8", "latin-1"))
            else:
                desc_b, _, val_b = rest.partition(b"\x00")
                desc = decode_text(desc_b, (cod,))
                val = decode_text(val_b, (cod, "utf-8", "latin-1"))
            desc = desc.replace("\x00", "")
            val = val.replace("\x00", "")
            if "AIGC" in desc.upper():
                hits.append(Hit("ID3v2 TXXX 帧（desc=%s）" % desc,
                                "@0x%X" % i, val))
            elif "AIGC" in val or '"Label"' in val:
                hits.append(Hit("ID3v2 TXXX 帧（desc=%s）" % desc, "@0x%X" % i, val,
                                "标识写在非 AIGC 描述中", standard=False))
        elif fid in (b"COMM", b"USLT", b"TIT2", b"TPE1") and b"AIGC" in body:
            hits.append(Hit("ID3v2 %s 帧" % fid.decode("latin-1"), "@0x%X" % i,
                            decode_text(body), "非标准位置，仅作线索",
                            standard=False))
        i += 10 + fsize
    return hits, meta


def parse_ogg(data):
    """Vorbis / Opus 注释头：KEY=AIGC。"""
    hits, meta = [], []
    if not data.startswith(b"OggS"):
        return hits, meta
    meta.append("Ogg 容器")
    for m in re.finditer(rb"(?:^|[\x00-\x20])(AIGC)=(.{0,3000}?)(?=[\x00-\x08]|$)",
                         data, re.S):
        hits.append(Hit("VORBIS_COMMENT 键 AIGC", "@0x%X" % m.start(1),
                        decode_text(m.group(2))))
    if not hits and b"AIGC" in data:
        hits += keyword_fallback(data, "OGG 全文件扫描")
    return hits, meta


def parse_flac(data):
    """FLAC METADATA_BLOCK type=4 (VORBIS_COMMENT)。"""
    hits, meta = [], []
    if data[:4] != b"fLaC":
        return hits, meta
    i = 4
    while i + 4 <= len(data):
        head = data[i]
        last = head & 0x80
        btype = head & 0x7F
        ln = int.from_bytes(data[i + 1:i + 4], "big")
        body = data[i + 4:i + 4 + ln]
        meta.append("metadata block type=%d len=%d" % (btype, ln))
        if btype == 4:
            p = 0
            vlen = int.from_bytes(body[0:4], "little")
            p = 4 + vlen
            cnt = int.from_bytes(body[p:p + 4], "little") if p + 4 <= len(body) else 0
            p += 4
            for _ in range(min(cnt, 512)):
                if p + 4 > len(body):
                    break
                clen = int.from_bytes(body[p:p + 4], "little")
                item = decode_text(body[p + 4:p + 4 + clen])
                p += 4 + clen
                if "=" not in item:
                    continue
                k, _, v = item.partition("=")
                meta.append("comment %s" % k)
                if "AIGC" in k.upper():
                    hits.append(Hit("VORBIS_COMMENT 键 %s" % k, "@0x%X" % i, v))
                elif "AIGC" in v:
                    hits.append(Hit("VORBIS_COMMENT 键 %s" % k, "@0x%X" % i, v,
                                    "标识写在非 AIGC 键名下", standard=False))
        if last:
            break
        i += 4 + ln
    return hits, meta


# --------------------------------------------------------------------------
# 视频：FLV / Matroska / AVI
# --------------------------------------------------------------------------
AMF0_END = b"\x00\x00\x09"


def amf0_walk(b, p, end, path, out, depth=0):
    """极简 AMF0 遍历，收集 (路径, 字符串值)。"""
    while p < end and depth < 16:
        t = b[p]
        p += 1
        if t == 0x00:
            p += 8
        elif t == 0x01:
            p += 1
        elif t == 0x02:
            if p + 2 > end:
                return
            ln = int.from_bytes(b[p:p + 2], "big")
            out.append((path, decode_text(b[p + 2:p + 2 + ln])))
            p += 2 + ln
        elif t in (0x03, 0x08):
            if t == 0x08:
                p += 4
            while p + 2 <= end:
                if b[p:p + 3] == AMF0_END:
                    p += 3
                    break
                kl = int.from_bytes(b[p:p + 2], "big")
                key = decode_text(b[p + 2:p + 2 + kl])
                p += 2 + kl
                if p >= end:
                    return
                p = amf0_value(b, p, end, path + key, out)
                if p < 0:
                    return
        elif t == 0x05 or t == 0x06:
            pass
        elif t == 0x07:
            p += 2
        elif t == 0x0A:
            if p + 4 > end:
                return
            cnt = int.from_bytes(b[p:p + 4], "big")
            p += 4
            for _ in range(cnt):
                p = amf0_value(b, p, end, path, out)
                if p < 0:
                    return
        elif t == 0x0B:
            p += 10
        elif t == 0x0C:
            if p + 4 > end:
                return
            ln = int.from_bytes(b[p:p + 4], "big")
            out.append((path, decode_text(b[p + 4:p + 4 + ln])))
            p += 4 + ln
        elif t == 0x0F:
            p += 4
        elif t in (0x10,):
            if p + 2 > end:
                return
            ln = int.from_bytes(b[p:p + 2], "big")
            p += 2 + ln
            p = amf0_skip_object(b, p)
        else:
            return
    return p


def amf0_skip_object(b, p):
    depth = 1
    while p + 2 <= len(b) and depth:
        if b[p:p + 3] == AMF0_END:
            return p + 3
        kl = int.from_bytes(b[p:p + 2], "big")
        p += 2 + kl
        if p >= len(b):
            return len(b)
        p = amf0_value(b, p, len(b), "", [])
        if p < 0:
            return len(b)
    return p


def amf0_value(b, p, end, path, out):
    if p >= end:
        return -1
    t = b[p]
    p += 1
    if t == 0x00:
        return p + 8
    if t == 0x01:
        return p + 1
    if t == 0x02:
        if p + 2 > end:
            return -1
        ln = int.from_bytes(b[p:p + 2], "big")
        out.append((path, decode_text(b[p + 2:p + 2 + ln])))
        return p + 2 + ln
    if t in (0x03, 0x08):
        p += 4 if t == 0x08 else 0
        return amf0_skip_object(b, p)
    if t in (0x05, 0x06):
        return p
    if t == 0x07:
        return p + 2
    if t == 0x0B:
        return p + 10
    if t == 0x0C:
        if p + 4 > end:
            return -1
        ln = int.from_bytes(b[p:p + 4], "big")
        out.append((path, decode_text(b[p + 4:p + 4 + ln])))
        return p + 4 + ln
    return -1


def parse_flv(data):
    hits, meta = [], []
    if data[:3] != b"FLV":
        return hits, meta
    meta.append("FLV header")
    i = 9 + 4
    n = len(data)
    while i + 11 <= n:
        tag_type = data[i]
        dsize = int.from_bytes(data[i + 1:i + 4], "big")
        body = data[i + 11:i + 11 + dsize]
        meta.append("tag type=%d size=%d @0x%X" % (tag_type, dsize, i))
        if tag_type == 18 and body:
            kv = []
            amf0_walk(body, 0, len(body), "", kv)
            for path, val in kv:
                if "AIGC" in path.upper():
                    hits.append(Hit("FLV script.onMetaData 键 %s" % path.strip("."),
                                    "@0x%X" % i, val))
                elif "AIGC" in val:
                    hits.append(Hit("FLV metadata 键 %s" % path.strip("."),
                                    "@0x%X" % i, val,
                                    "标识写在非 AIGC 键名下", standard=False))
        i += 11 + dsize + 4
    return hits, meta


def ebml_read_id(b, p):
    if p >= len(b):
        return None, p
    f = b[p]
    ln = 1
    m = 0x80
    while ln <= 8 and not (f & m) and m:
        m >>= 1
        ln += 1
    if p + ln > len(b):
        return None, p
    return int.from_bytes(b[p:p + ln], "big"), p + ln


def ebml_read_size(b, p):
    if p >= len(b):
        return None, p
    f = b[p]
    ln = 1
    m = 0x80
    while ln <= 8 and not (f & m) and m:
        m >>= 1
        ln += 1
    if p + ln > len(b):
        return None, p
    v = f & (m - 1)
    for k in range(1, ln):
        v = (v << 8) | b[p + k]
    unknown = v == (1 << (7 * ln)) - 1
    return (None if unknown else v), p + ln


def parse_mkv(data):
    """Matroska/WebM：Segment.Tags.Tag.SimpleTag.{TagName,TagString}。"""
    hits, meta = [], []
    if not data.startswith(b"\x1a\x45\xdf\xa3"):
        return hits, meta
    meta.append("EBML header")
    tags_id = b"\x12\x54\xc3\x67"      # Tags
    for m in re.finditer(re.escape(tags_id), data):
        p = m.end()
        size, p = ebml_read_size(data, p)
        if size is None:
            end = len(data)
        else:
            end = min(p + size, len(data))
        while p < end:
            cid, p2 = ebml_read_id(data, p)
            if cid is None:
                break
            sz, p3 = ebml_read_size(data, p2)
            if sz is None:
                break
            cend = min(p3 + sz, end)
            if cid == 0x7373:      # Tag
                tname = tstr = ""
                q = p3
                while q < cend:
                    sid, q2 = ebml_read_id(data, q)
                    if sid is None:
                        break
                    ssz, q3 = ebml_read_size(data, q2)
                    if ssz is None:
                        break
                    send = min(q3 + ssz, cend)
                    if sid == 0x67C8:      # SimpleTag
                        r = q3
                        while r < send:
                            uid, r2 = ebml_read_id(data, r)
                            if uid is None:
                                break
                            usz, r3 = ebml_read_size(data, r2)
                            if usz is None:
                                break
                            uend = min(r3 + usz, send)
                            if uid == 0x45A3:
                                tname = decode_text(data[r3:uend])
                            elif uid == 0x4487:
                                tstr = decode_text(data[r3:uend])
                            r = uend
                        if "AIGC" in tname.upper():
                            hits.append(Hit("Matroska SimpleTag %s" % tname,
                                            "@0x%X" % m.start(), tstr))
                        elif "AIGC" in tstr:
                            hits.append(Hit("Matroska SimpleTag %s" % tname,
                                            "@0x%X" % m.start(), tstr,
                                            "标识写在非 AIGC 标签名下",
                                            standard=False))
                    q = send
            p = cend
    if not hits and b"AIGC" in data:
        hits += keyword_fallback(data, "MKV 全文件扫描")
    return hits, meta


# --------------------------------------------------------------------------
# 文本 / 办公文档
# --------------------------------------------------------------------------
def parse_pdf(data):
    hits, meta = [], []
    if not data.startswith(b"%PDF"):
        return hits, meta
    meta.append("PDF " + decode_text(data[1:9], ("latin-1",)))
    # 1) Document Information Dictionary 中的 /AIGC
    for m in re.finditer(rb"/AIGC\s*", data):
        p = m.end()
        if p < len(data) and data[p:p + 1] == b"(":
            txt, _ = pdf_string(data, p)
            hits.append(Hit("PDF Info 字典 /AIGC", "@0x%X" % m.start(), txt))
        elif p < len(data) and data[p:p + 1] == b"<":
            q = data.find(b">", p)
            if q > p:
                raw = bytes.fromhex(re.sub(rb"[^0-9A-Fa-f]", b"", data[p + 1:q]).decode())
                hits.append(Hit("PDF Info 字典 /AIGC(十六进制)",
                                "@0x%X" % m.start(), decode_text(raw)))
    # 2) XMP：明文或 Flate 压缩流
    if b"www.tc260.org.cn/ns/AIGC" in data or b"TC260:AIGC" in data:
        hits += xmp_hits(data, "PDF 内嵌 XMP（明文）")
    for m in re.finditer(rb"stream\r?\n", data):
        start = m.end()
        end = data.find(b"endstream", start)
        if end < 0:
            continue
        chunk = data[start:end]
        try:
            dec = zlib.decompress(chunk)
        except Exception:
            continue
        if b"AIGC" in dec and b"xmp" in dec.lower():
            hits += xmp_hits(dec, "@0x%X 压缩 XMP 流" % start)
    if not hits and b"AIGC" in data:
        meta.append("全文件出现 AIGC 关键字但不在标准位置")
    return hits, meta


def pdf_string(data, p):
    """解析 PDF 字面量字符串 ( ... )，支持嵌套与转义。"""
    depth = 0
    i = p
    out = bytearray()
    while i < len(data):
        c = data[i:i + 1]
        if c == b"\\":
            nxt = data[i + 1:i + 2]
            if nxt in (b"(", b")", b"\\", b'"', b"'"):
                out += nxt
                i += 2
                continue
            if nxt in (b"n", b"r", b"t"):
                out += {b"n": b"\n", b"r": b"\r", b"t": b"\t"}[nxt]
                i += 2
                continue
            out += c
            i += 1
            continue
        if c == b"(":
            depth += 1
            if depth == 1:
                i += 1
                continue
        elif c == b")":
            depth -= 1
            if depth == 0:
                i += 1
                break
        out += c
        i += 1
    return decode_text(bytes(out)), i


OOXML_AIGC_RE = re.compile(r'name\s*=\s*"([^"]*AIGC[^"]*)"', re.I)


def parse_zip_like(path):
    """docx/xlsx/pptx/UOF/OFD/xmind/posm/posf：都是 ZIP 容器。"""
    hits, meta = [], []
    try:
        zf = zipfile.ZipFile(path)
    except Exception as e:
        return hits, meta + ["ZIP 打开失败: %s" % e]
    names = zf.namelist()
    meta.append("ZIP 条目 %d 个" % len(names))
    for n in names:
        meta.append("  " + n)

    def read_json_key(entry, key="AIGC"):
        try:
            obj = json.loads(zf.read(entry).decode("utf-8", "ignore"))
        except Exception:
            return None
        if isinstance(obj, dict) and key in obj:
            v = obj[key]
            return v if isinstance(v, str) else json.dumps(v, ensure_ascii=False)
        return None

    # OOXML：docProps/custom.xml 的 <property name="AIGC"><vt:lpwstr>
    if "docProps/custom.xml" in names:
        raw = zf.read("docProps/custom.xml").decode("utf-8", "ignore")
        for m in re.finditer(r"<(?:\w+:)?property\b[^>]*name=\"([^\"]*)\"[^>]*>(.*?)"
                             r"</(?:\w+:)?property>", raw, re.S):
            name, body = m.group(1), m.group(2)
            val = re.sub(r"<[^>]+>", "", body).strip()
            meta.append("custom.xml property=%s" % name)
            if "AIGC" in name.upper():
                hits.append(Hit("OOXML docProps/custom.xml (%s)" % name,
                                "docProps/custom.xml", val))
            elif "AIGC" in val:
                hits.append(Hit("OOXML 自定义属性 %s" % name, "docProps/custom.xml",
                                val, "标识写在非 AIGC 属性名下", standard=False))
    # UOF：_meta/meta.xml 的 自定义元数据_5210
    for n in names:
        if n.lower().endswith("meta.xml") and ("_meta" in n or n.lower() == "meta.xml"):
            raw = zf.read(n).decode("utf-8", "ignore")
            if "自定义元数据" not in raw and "AIGC" not in raw:
                continue
            for m in re.finditer(r"<[^>]*自定义元数据_5210[^>]*名称_5211=\"([^\"]*)\"[^>]*>"
                                 r"(.*?)</", raw, re.S):
                meta.append("%s 自定义元数据=%s" % (n, m.group(1)))
                if "AIGC" in m.group(1).upper():
                    hits.append(Hit("UOF _meta/meta.xml (名称_5211=%s)" % m.group(1),
                                    n, m.group(2).strip()))
    # OFD：Document.xml 的 CustomDatas/CustomData
    for n in names:
        if not n.lower().endswith(".xml"):
            continue
        try:
            raw = zf.read(n).decode("utf-8", "ignore")
        except Exception:
            continue
        if "CustomData" not in raw:
            continue
        for m in re.finditer(r"<(?:\w+:)?CustomData\b[^>]*name=\"([^\"]*)\"[^>]*>"
                             r"(.*?)</(?:\w+:)?CustomData>", raw, re.S):
            meta.append("%s CustomData name=%s" % (n, m.group(1)))
            if "AIGC" in m.group(1).upper():
                hits.append(Hit("OFD CustomData (%s)" % m.group(1), n,
                                m.group(2).strip()))
    # xmind / posm / posf：metadata.json / meta.json
    for entry, label in (("metadata.json", "xmind metadata.json"),
                         ("meta.json", "posm/posf meta.json")):
        if entry in names:
            v = read_json_key(entry)
            meta.append("%s AIGC=%s" % (entry, "有" if v else "无"))
            if v:
                hits.append(Hit(label + " 节点 AIGC", entry, v))
    return hits, meta


def parse_markdown(data):
    """Markdown：标识嵌入文件头部（front matter / 注释）。标准用图示意。"""
    hits, meta = [], []
    text = decode_text(data)
    head = text[:8192]
    meta.append("Markdown，前 %d 字节参与头部检测" % min(len(text), 8192))
    m = re.match(r"^---\s*\n(.*?)\n---\s*(\n|$)", text, re.S)
    if m:
        meta.append("检测到 YAML front matter")
        fm = m.group(1)
        for line in fm.splitlines():
            if re.match(r"^\s*AIGC\s*:", line, re.I):
                hits.append(Hit("Markdown front matter 键 AIGC",
                                "头部第 %d 行" % (fm[:fm.find(line)].count("\n") + 2),
                                line.split(":", 1)[1].strip().strip("'\"")))
    for m in re.finditer(r"<!--(.*?)-->", head, re.S):
        if "AIGC" in m.group(1):
            hits.append(Hit("Markdown HTML 注释", "头部", m.group(1).strip()))
    for obj in json_objects(head):
        if "AIGC" in obj or '"Label"' in obj:
            hits.append(Hit("Markdown 头部 JSON 片段", "头部", obj))
            break
    if not hits:
        idx = text.find("AIGC")
        if idx >= 0:
            hits.append(Hit("Markdown 正文出现 AIGC 关键字", "偏移 %d" % idx,
                            text[max(0, idx - 40):idx + 400],
                            "不在头部，或为正文内容而非标识", standard=False))
    return hits, meta


# --------------------------------------------------------------------------
# C2PA / JUMBF 溯源清单（国际体系，非 GB 45438 标准，仅作旁证）
#   中国标准要求的是 AIGC 键的 JSON；C2PA 是另一条独立证据线，
#   两者可并存也常见互斥。取证时不能只看一条。
# --------------------------------------------------------------------------
def cbor_load(b, p=0, depth=0):
    """最小 CBOR 解码器：只求正确切分与取值，不求完备。"""
    if p >= len(b) or depth > 32:
        raise ValueError("cbor eof")
    ib = b[p]
    p += 1
    major, ai = ib >> 5, ib & 0x1F
    if ai < 24:
        val = ai
    elif ai == 24:
        val = b[p]
        p += 1
    elif ai == 25:
        val = int.from_bytes(b[p:p + 2], "big")
        p += 2
    elif ai == 26:
        val = int.from_bytes(b[p:p + 4], "big")
        p += 4
    elif ai == 27:
        val = int.from_bytes(b[p:p + 8], "big")
        p += 8
    elif ai == 31:
        val = None
    else:
        raise ValueError("bad additional info")
    if major == 0:
        return val, p
    if major == 1:
        return -1 - val, p
    if major == 2:
        if val is None:
            out = bytearray()
            while p < len(b) and b[p] != 0xFF:
                chunk, p = cbor_load(b, p, depth + 1)
                out += chunk
            return (bytes(out), p + 1) if p < len(b) else (bytes(out), len(b))
        return b[p:p + val], p + val
    if major == 3:
        if val is None:
            out = ""
            while p < len(b) and b[p] != 0xFF:
                chunk, p = cbor_load(b, p, depth + 1)
                out += chunk if isinstance(chunk, str) else ""
            return out, (p + 1 if p < len(b) else len(b))
        return b[p:p + val].decode("utf-8", "replace"), p + val
    if major == 4:
        arr = []
        if val is None:
            while p < len(b) and b[p] != 0xFF:
                v, p = cbor_load(b, p, depth + 1)
                arr.append(v)
            return arr, (p + 1 if p < len(b) else len(b))
        for _ in range(val):
            v, p = cbor_load(b, p, depth + 1)
            arr.append(v)
        return arr, p
    if major == 5:
        mp = {}
        if val is None:
            while p < len(b) and b[p] != 0xFF:
                k, p = cbor_load(b, p, depth + 1)
                v, p = cbor_load(b, p, depth + 1)
                mp[k if isinstance(k, str) else str(k)] = v
            return mp, (p + 1 if p < len(b) else len(b))
        for _ in range(val):
            k, p = cbor_load(b, p, depth + 1)
            v, p = cbor_load(b, p, depth + 1)
            mp[k if isinstance(k, str) else str(k)] = v
        return mp, p
    if major == 6:                                   # tag
        v, p = cbor_load(b, p, depth + 1)
        return v, p
    if ai == 20:
        return False, p
    if ai == 21:
        return True, p
    return None, p                                   # null/undefined/float 不关心


def cbor_find(obj, key, depth=0):
    """深度优先收集所有同名键的值。"""
    res = []
    if depth > 24:
        return res
    if isinstance(obj, dict):
        for k, v in obj.items():
            if k == key:
                res.append(v)
            res += cbor_find(v, key, depth + 1)
    elif isinstance(obj, list):
        for x in obj:
            res += cbor_find(x, key, depth + 1)
    return res


def _jumbf_contents(data, start, end, out, depth=0):
    """遍历 JUMBF superbox，取出每个内容盒的字节。"""
    p = start
    while p + 8 <= end and depth < 8:
        size = int.from_bytes(data[p:p + 4], "big")
        typ = data[p + 4:p + 8]
        if size < 8 or p + size > end:
            break
        if typ == b"jumb":
            q = p + 8
            first_non_desc = None
            while q + 8 <= p + size:
                s2 = int.from_bytes(data[q:q + 4], "big")
                t2 = data[q + 4:q + 8]
                if s2 < 8 or q + s2 > p + size:
                    break
                if t2 != b"jumd" and first_non_desc is None:
                    first_non_desc = (q + 8, q + s2)
                q += s2
            if first_non_desc:
                out.append((first_non_desc[0], first_non_desc[1]))
            _jumbf_contents(data, p + 8, p + size, out, depth + 1)
        p += size


C2PA_UUID = bytes.fromhex("d8fec3d61b0e483c92975828877ec481")


def c2pa_candidates(data, kind):
    """按容器定位 JUMBF 数据块，返回 [(说明, bytes)]。"""
    res = []
    if kind == "png":
        i = 8
        while i + 8 <= len(data):
            ln = int.from_bytes(data[i:i + 4], "big")
            typ = data[i + 4:i + 8]
            if typ == b"caBX":
                res.append(("PNG 私有 chunk caBX @0x%X" % i, data[i + 8:i + 8 + ln]))
            if typ == b"IEND":
                break
            i += 12 + ln
    elif kind == "jpeg":
        i = 2
        while i + 4 <= len(data):
            if data[i] != 0xFF:
                i += 1
                continue
            m = data[i + 1]
            if m == 0xDA:
                break
            ln = int.from_bytes(data[i + 2:i + 4], "big")
            body = data[i + 4:i + 2 + ln]
            if m == 0xEB and body[:2] == b"JP":
                j = body.find(b"jumb")
                res.append(("JPEG APP11(JUMBF) @0x%X" % i,
                            body[j - 4:] if j >= 4 else body))
            i += 2 + ln
    elif kind in ("webp", "wav", "avi"):
        i = 12
        while i + 8 <= len(data):
            cid = data[i:i + 4]
            ln = int.from_bytes(data[i + 4:i + 8], "little")
            if cid in (b"C2PA", b"caBX"):
                res.append(("RIFF chunk %s @0x%X" % (cid.decode("latin-1"), i),
                            data[i + 8:i + 8 + ln]))
            i += 8 + ln + (ln & 1)
    elif kind == "bmff":
        for typ, s, e, hdr in bmff_boxes(data, 0, len(data)):
            if typ == b"uuid" and data[s + hdr:s + hdr + 16] == C2PA_UUID:
                res.append(("BMFF uuid box @0x%X" % s, data[s + hdr + 16:e]))
    # 兜底：全文件出现 jumdc2pa 就记录存在
    if not res and b"jumdc2pa" in data:
        j = data.find(b"jumdc2pa")
        res.append(("全文件 jumdc2pa @0x%X" % j, data[max(0, j - 4):j + 200000]))
    return res


def detect_c2pa(data, kind):
    """返回 C2PA 清单摘要 dict，未检出返回 None。"""
    cands = c2pa_candidates(data, kind)
    total = sum(len(b) for _l, b in cands)
    if not cands:
        return None
    objs, strings, locs = [], set(), []
    for label, blob in cands:
        locs.append(label)
        contents = []
        if b"jumb" in blob:
            _jumbf_contents(blob, 0, len(blob), contents)
        for s, e in contents:
            chunk = blob[s:e]
            try:
                obj, _ = cbor_load(chunk, 0)
                if isinstance(obj, (dict, list)):
                    objs.append(obj)
                    continue
            except Exception:
                pass
            for t in re.findall(rb"[\x20-\x7e]{5,}", chunk):
                strings.add(t.decode("latin-1"))
        for t in re.findall(rb"[\x20-\x7e]{5,}", blob):
            strings.add(t.decode("latin-1"))
    info = {"locations": locs, "size": total, "urn": "", "generator": "",
            "software": "", "source_type": "", "actions": [], "when": "",
            "signer": "", "has_signature": False, "strings": sorted(strings)}
    for obj in objs:
        for g in cbor_find(obj, "claim_generator_info"):
            for item in (g if isinstance(g, list) else [g]):
                if isinstance(item, dict) and item.get("name"):
                    info["generator"] = str(item["name"])
                    if item.get("version"):
                        info["generator"] += " " + str(item["version"])
                    info["generator"] = info["generator"][:80]
        for a in cbor_find(obj, "softwareAgent"):
            if isinstance(a, dict) and a.get("name"):
                info["software"] = "%s %s" % (a["name"], a.get("version", ""))
                info["software"] = info["software"].strip()
        for d in cbor_find(obj, "digitalSourceType"):
            if isinstance(d, str):
                info["source_type"] = d
        for w in cbor_find(obj, "when"):
            if isinstance(w, str) and not info["when"]:
                info["when"] = w
        for act in cbor_find(obj, "action"):
            if isinstance(act, str) and act not in info["actions"]:
                info["actions"].append(act)
        if cbor_find(obj, "signature") or cbor_find(obj, "sigTst"):
            info["has_signature"] = True
    if not info["has_signature"] and "c2pa.signature" in strings:
        info["has_signature"] = True
    for s in strings:
        m = re.search(r"urn:c2pa:[0-9a-fA-F-]{8,}", s)
        if m and not info["urn"]:
            info["urn"] = m.group(0)
        if not info["signer"]:
            # 证书 CN 常与版本号粘连（如 "Google LLC1"），按前缀取最短命中
            for cand in sorted(strings, key=len):
                hit = next((k for k in KNOWN_SIGNERS if cand.startswith(k)), None)
                if hit:
                    info["signer"] = hit
                    break
    if not info["generator"]:
        for s in strings:
            m = re.search(r"(OpenAI[\w .-]*|ChatGPT|gpt-image[\w.-]*|Google[\w .-]*|"
                          r"Gemini|Imagen[\w.-]*|DALL[·\-. ]?E[\w.-]*|Midjourney|"
                          r"Adobe Firefly)", s)
            if m:
                info["generator"] = m.group(1).strip()
                break
    return info


KNOWN_SIGNERS = ("Google LLC", "OpenAI", "Adobe Inc.", "Adobe", "Microsoft Corporation",
                 "Truepic", "Leica", "Nikon", "Sony", "Canon")

SOURCE_TYPE_CN = {
    "trainedAlgorithmicMedia": "训练算法生成媒体（IPTC 定义：AI 生成）",
    "compositeWithTrainedAlgorithmicMedia": "含 AI 生成成分的合成内容",
    "algorithmicallyEnhanced": "算法增强内容",
    "digitalCapture": "数字拍摄（原始内容）",
}


# --------------------------------------------------------------------------
# 兜底扫描
# --------------------------------------------------------------------------
def keyword_fallback(data, loc):
    hits = []
    for m in re.finditer(rb"AIGC", data):
        s = max(0, m.start() - 24)
        ctx_b = data[s:m.start() + 800]
        ctx = decode_text(ctx_b, ("utf-8", "latin-1"))
        if "{" not in ctx and "Label" not in ctx:
            continue
        hits.append(Hit(loc + " 关键字 @0x%X" % m.start(), "@0x%X" % m.start(), ctx,
                        "非标准位置，需人工核验", standard=False))
        if len(hits) >= 8:
            break
    return hits


# --------------------------------------------------------------------------
# 分派
# --------------------------------------------------------------------------
IMG_EXT = {".jpg", ".jpeg", ".jpe", ".jfif", ".png", ".tif", ".tiff", ".webp",
           ".gif", ".heic", ".heif", ".avif"}
AUD_EXT = {".wav", ".mp3", ".ogg", ".oga", ".opus", ".flac", ".m4a", ".aac",
           ".wma", ".amr"}
VID_EXT = {".mp4", ".mov", ".m4v", ".flv", ".mkv", ".webm", ".avi", ".wmv", ".ts"}
DOC_EXT = {".docx", ".docm", ".dotx", ".xlsx", ".xlsm", ".xltx", ".pptx", ".pptm",
           ".potx", ".uot", ".uott", ".uos", ".uost", ".uop", ".uopt",
           ".ofd", ".xmind", ".posm", ".posf"}
TXT_EXT = {".md", ".markdown", ".txt", ".json", ".xml", ".html", ".htm", ".csv",
           ".srt", ".log"}


def sniff(data):
    if data[:2] == b"\xff\xd8":
        return "jpeg"
    if data[:8] == b"\x89PNG\r\n\x1a\n":
        return "png"
    if data[:4] in (b"II*\x00", b"MM\x00*"):
        return "tiff"
    if data[:4] == b"RIFF" and data[8:12] == b"WAVE":
        return "wav"
    if data[:4] == b"RIFF" and data[8:12] == b"AVI ":
        return "avi"
    if data[:4] == b"RIFF" and data[8:12] == b"WEBP":
        return "webp"
    if data[:3] == b"ID3":
        return "mp3"
    if data[:4] == b"fLaC":
        return "flac"
    if data[:4] == b"OggS":
        return "ogg"
    if data[:3] == b"FLV":
        return "flv"
    if data[:4] == b"\x1aE\xdf\xa3":
        return "mkv"
    if data[:5] == b"%PDF-":
        return "pdf"
    if data[4:8] in (b"ftyp", b"moov", b"mdat", b"free", b"skip"):
        return "bmff"
    if data[:6] in (b"GIF87a", b"GIF89a"):
        return "gif"
    if data[:4] == b"PK\x03\x04":
        return "zip"
    return "unknown"


KIND_DESC = {
    "jpeg": "JPEG 图片", "png": "PNG 图片", "tiff": "TIFF 图片",
    "webp": "WebP 图片", "gif": "GIF 图片", "heic": "HEIF/HEIC 图片",
    "wav": "WAV 音频", "mp3": "MP3 音频", "ogg": "OGG 音频",
    "flac": "FLAC 音频", "m4a": "M4A 音频",
    "bmff": "BMFF（MP4/MOV/M4A/HEIC）",
    "flv": "FLV 视频", "mkv": "Matroska（MKV/WebM）", "avi": "AVI 视频",
    "pdf": "PDF 文本", "zip": "ZIP 容器（OOXML/UOF/OFD/xmind/posm）",
    "md": "Markdown 文本", "text": "纯文本", "unknown": "未知格式",
}


def analyze_file(path, dump=False):
    with open(path, "rb") as f:
        data = f.read()
    ext = os.path.splitext(path)[1].lower()
    kind = sniff(data)
    if kind == "unknown":
        if ext in IMG_EXT:
            kind = "heic" if ext in (".heic", ".heif", ".avif") else "unknown"
        elif ext == ".md" or ext in (".markdown",):
            kind = "md"
        elif ext in TXT_EXT:
            kind = "text"
        elif ext in DOC_EXT:
            kind = "zip"

    hits, meta = [], []
    if kind == "jpeg":
        hits, meta = parse_jpeg(data)
    elif kind == "png":
        hits, meta = parse_png(data)
    elif kind == "tiff":
        hits, meta = parse_tiff_file(data)
    elif kind in ("wav", "avi", "webp"):
        hits, meta = parse_riff(data, kind)
    elif kind == "gif":
        hits, meta = parse_gif(data)
    elif kind == "mp3":
        hits, meta = parse_mp3(data)
    elif kind == "flac":
        hits, meta = parse_flac(data)
    elif kind == "ogg":
        hits, meta = parse_ogg(data)
    elif kind == "bmff":
        hits, meta = parse_bmff(data)
    elif kind == "flv":
        hits, meta = parse_flv(data)
    elif kind == "mkv":
        hits, meta = parse_mkv(data)
    elif kind == "pdf":
        hits, meta = parse_pdf(data)
    elif kind == "zip":
        hits, meta = parse_zip_like(path)
    elif kind == "md":
        hits, meta = parse_markdown(data)
    else:
        hits, meta = [], ["未识别格式，仅做关键字扫描"]

    # 兜底：全文件关键字扫描（标准位置未命中时补充线索）
    if kind not in ("zip", "md"):
        std = [h for h in hits if h.standard]
        if not std:
            fb = keyword_fallback(data, "全文件")
            known = {(h.location, h.channel) for h in hits}
            hits += [h for h in fb if (h.location, h.channel) not in known]

    c2pa = None
    try:
        c2pa = detect_c2pa(data, kind)
    except Exception:
        c2pa = None
    return {
        "file": os.path.abspath(path),
        "name": os.path.basename(path),
        "size": len(data),
        "kind": kind,
        "kind_desc": KIND_DESC.get(kind, kind),
        "hits": hits,
        "meta": meta,
        "c2pa": c2pa,
        "dump": meta if dump else None,
    }


def parse_gif(data):
    hits, meta = [], []
    if data[:6] not in (b"GIF87a", b"GIF89a"):
        return hits, meta
    meta.append("GIF " + decode_text(data[:6], ("latin-1",)))
    idx = 0
    while True:
        j = data.find(b"\x21\xff\x0b", idx)
        if j < 0:
            break
        app = data[j + 3:j + 14]
        k, buf = j + 14, bytearray()
        while k < len(data):
            ln = data[k]
            if ln == 0:
                break
            buf += data[k + 1:k + 1 + ln]
            k += 1 + ln
        meta.append("ApplicationExtension %s @0x%X"
                    % (decode_text(app, ("latin-1",)).strip(), j))
        if b"XMP" in app or b"xmp" in bytes(buf[:256]).lower():
            hits += xmp_hits(bytes(buf), "GIF ApplicationExtension XMP @0x%X" % j)
        idx = j + 3
    return hits, meta


# --------------------------------------------------------------------------
# 校验与判定
# --------------------------------------------------------------------------
def validate_only(fields):
    checks = []

    def add(name, ok, detail=""):
        checks.append({"item": name, "ok": bool(ok), "detail": detail})

    if not fields:
        add("标识字段可解析", False, "未解析出 JSON 字段")
        return checks, []
    add("标识字段可解析", True)
    miss = [f for f in FIELDS if f not in fields]
    empty = [f for f in ("Label", "ContentProducer", "ProduceID")
             if not str(fields.get(f, "")).strip()]
    detail = "七项均存在（其中 Label/ContentProducer/ProduceID 为必填非空）" \
        if not miss and not empty else ""
    if miss:
        detail = "缺失字段: " + ", ".join(miss)
    if empty:
        detail += ("；" if detail else "") + "必填字段为空: " + ", ".join(empty)
    add("七要素齐全（附录 E）", not miss and not empty, detail)
    label = str(fields.get("Label", ""))
    add("Label 取值合法（1/2/3）", label in ("1", "2", "3"),
        "Label=%s → %s" % (label, LABEL_DESC.get(label, "非法取值")) if label else "缺失")
    for key in ("ContentProducer", "ContentPropagator"):
        code = fields.get(key) or ""
        if not code:
            continue
        d = decode_provider_code(code)
        if d:
            ok = True
            detail = describe_provider_code(code)
            if d["subject_type"] == "组织" and d["bind"] != "统一社会信用代码":
                ok = False
                detail += "  ← 组织主体只能绑定统一社会信用代码"
            add("%s 为 27 位编码" % key, ok, detail)
        elif re.fullmatch(r"[0-9A-Z]{27}", code):
            add("%s 为 27 位编码" % key, False,
                "长度 27 位但不符合 TC260-PG-20252A 结构（前 4 位应形如 0011/0021）："
                + code)
        else:
            # 附录 E d)/g) 明确允许"名称或编码"，用名称本身不违规
            add("%s 要素取值方式" % key, True,
                "以名称存储（附录 E 允许“名称或编码”），但名称无法反查主体，"
                "溯源能力弱于 27 位编码：" + code)
    # 附录 E 注 1：首次写入时，传播方要素应与生成方一致
    cp = (fields.get("ContentPropagator") or "").strip()
    pid = (fields.get("PropagateID") or "").strip()
    if not cp and not pid:
        add("传播方要素已填写（附录 E 注 1）", False,
            "ContentPropagator 与 PropagateID 均为空；首次写入时应与生成方一致")
    elif not cp or not pid:
        add("传播方要素已填写（附录 E 注 1）", False,
            "传播方要素只填了一半（提供者=%r，编号=%r）" % (cp, pid))
    else:
        same = (cp == (fields.get("ContentProducer") or "").strip()
                and pid == (fields.get("ProduceID") or "").strip())
        add("传播方要素已填写（附录 E 注 1）", True,
            "与生成方一致（首次写入）" if same else "与生成方不同（已被传播方更新）")
    bad_fields = {}
    for f in FIELDS:
        v = fields.get(f)
        if isinstance(v, str) and v:
            bad = check_charset(v)
            if bad:
                bad_fields[f] = bad
    add("字符集符合附录 E j)", not bad_fields,
        "; ".join("%s 含非法字符 %r" % (k, v) for k, v in bad_fields.items()) or "通过")
    sd = []
    for f in ("ReservedCode1", "ReservedCode2"):
        v = fields.get(f) or ""
        if "SecurityData" in v:
            try:
                obj = json.loads(v.replace('\\"', '"'))
                sd.append((f, obj.get("SecurityData", obj)))
            except Exception:
                sd.append((f, {"_raw": v}))
    return checks, sd


def summarize_sd(sd):
    """解析 TC260-PG-202511A 的安全防护信息。"""
    lines = []
    for field, obj in sd:
        if "_raw" in obj:
            lines.append("%s: 含 SecurityData 但 JSON 解析失败" % field)
            continue
        typ = obj.get("Type", "?")
        ver = obj.get("Version", "?")
        lines.append("%s: SecurityData Type=%s Version=%s" % (field, typ, ver))
        for b in obj.get("Bindings", []) or []:
            alg = b.get("AlgID", "")
            lines.append("  绑定 [%s] %s 算法=%s(%s) 选取=%s 值=%s"
                         % (b.get("ID", "-"), b.get("Type", "?"), alg,
                            OID_NAME.get(alg, "未知 OID"), b.get("CntSel", "-"),
                            (b.get("Value", "") or "")[:32] + "…"))
        for p in obj.get("PubSD", []) or []:
            t = p.get("Type")
            if t == "DS":
                alg = p.get("AlgID", "")
                lines.append("  数字签名 %s 签名值 %d 字符"
                             % (OID_NAME.get(alg, alg), len(p.get("Signature", ""))))
            elif t == "PubKey":
                lines.append("  公钥 算法=%s" % OID_NAME.get(p.get("AlgID", ""), p.get("AlgID")))
            elif t == "ExLink":
                lines.append("  外部验证链接 %s" % p.get("Value", ""))
        for p in obj.get("PrivSD", []) or []:
            lines.append("  非公开验证信息 Type=%s" % p.get("Type", "?"))
    return lines


def verdict_of(info):
    hits = info["hits"]
    std = [h for h in hits if h.standard]
    if not hits:
        return "not_found", "未检出文件元数据隐式标识"
    if not std:
        return "informal", "检出 AIGC 相关信息，但不在标准规定位置"
    return "found", "检出标准位置的文件元数据隐式标识"


# --------------------------------------------------------------------------
# 报告
# --------------------------------------------------------------------------
BAR = "=" * 74


CN_NUM = ["一", "二", "三", "四", "五", "六", "七", "八"]


def render(info, checks, fields, mode, notes, sd_lines, dump=False):
    out = []
    n = [0]

    def sec(title):
        n[0] += 1
        out.append("")
        out.append("%s、%s" % (CN_NUM[min(n[0] - 1, 7)], title))

    out.append(BAR)
    out.append("文件: %s" % info["name"])
    out.append("路径: %s" % info["file"])
    out.append("格式: %s    大小: %s 字节" % (info["kind_desc"], format(info["size"], ",")))
    out.append(BAR)

    v, vtext = verdict_of(info)
    c2pa = info.get("c2pa")
    icon = {"found": "[检出]", "informal": "[疑似]", "not_found": "[未检出]"}[v]
    sec("中国标准标识（GB 45438-2025）：%s %s" % (icon, vtext))
    if not info["hits"]:
        out.append("    （无任何命中）")
    for i, h in enumerate(info["hits"], 1):
        tag = "标准位置" if h.standard else "非标准/线索"
        out.append("  %d) [%s] %s" % (i, tag, h.channel))
        out.append("     位置: %s" % h.location)
        raw0 = (h.raw or "").strip()
        raw = html.unescape(raw0).replace("\n", " ")
        # XMP 常见实体转义（&quot;），展示还原后的可读形态
        esc = "（原文为 XML 实体转义）" if raw != raw0.strip() else ""
        out.append("     原文: %s%s" % (raw[:600] + ("…" if len(raw) > 600 else ""), esc))
        if h.note:
            out.append("     备注: %s" % h.note)

    sec("标识内容解析")
    if fields:
        out.append("  存储形态: %s" % {
            "wrapped": '{"AIGC":{...}}（附录 E 外层格式）',
            "inner": "{...}（内层字段，容器键名即 AIGC）",
            "partial": "非完整 JSON（仅正则提取）"}.get(mode, mode))
        for f in FIELDS:
            val = fields.get(f, "")
            out.append("  %-18s = %s" % (f, val if val else "（空）"))
        label = str(fields.get("Label", ""))
        if label in LABEL_DESC:
            out.append("  %-18s → %s" % ("Label 含义", LABEL_DESC[label]))
        for key in ("ContentProducer", "ContentPropagator"):
            d = describe_provider_code(fields.get(key) or "")
            if d:
                out.append("  %-18s → %s" % (key + " 解码", d))
    else:
        out.append("  （无可解析字段）")
    for note in notes:
        out.append("  提示: %s" % note)

    if sd_lines:
        sec("安全防护信息（TC260-PG-202511A）")
        for line in sd_lines:
            out.append("  " + line)

    sec("合规校验（GB 45438-2025 附录 E）")
    if not fields:
        out.append("  （未解析出标识字段，校验不适用）")
    for c in (checks if fields else []):
        out.append("  [%s] %s%s" % ("✓" if c["ok"] else "✗", c["item"],
                                    ("  —— " + c["detail"]) if c["detail"] else ""))

    nstd = len([h for h in info["hits"] if h.standard])
    if nstd > 1:
        out.append("  [!] 检测到 %d 处标准位置标识；GB 45438-2025 6.1 c) 要求"
                   "文件中仅保留一份，传播方应更新原标识而非另写一份" % nstd)

    if c2pa:
        sec("其他溯源体系：C2PA 内容凭证（非 GB 45438，仅作旁证）")
        out.append("  检出：%s，合计 %s 字节"
                   % ("；".join(c2pa["locations"]), format(c2pa["size"], ",")))
        if c2pa["urn"]:
            out.append("  清单标识: %s" % c2pa["urn"])
        if c2pa["generator"]:
            out.append("  生成工具: %s" % c2pa["generator"])
        if c2pa["software"]:
            out.append("  软件代理: %s" % c2pa["software"])
        if c2pa["source_type"]:
            tail = c2pa["source_type"].rsplit("/", 1)[-1]
            out.append("  数字源类型: %s（%s）" % (tail, SOURCE_TYPE_CN.get(tail, "IPTC 代码")))
            out.append("               %s" % c2pa["source_type"])
        if c2pa["actions"]:
            out.append("  记录动作: %s" % " / ".join(c2pa["actions"]))
        if c2pa["when"]:
            out.append("  记录时间: %s" % c2pa["when"])
        if c2pa["signer"]:
            out.append("  签名主体: %s" % c2pa["signer"])
        out.append("  数字签名: %s" % ("有（含 X.509 证书链，可离线验签）"
                                       if c2pa["has_signature"] else "未识别到"))

    sec("结论")
    ok_all = checks and all(c["ok"] for c in checks)
    if v == "found":
        if ok_all:
            out.append("  检出合规的文件元数据隐式标识。")
            if fields and str(fields.get("Label")) in LABEL_DESC:
                out.append("  该文件按标识应认定为：%s。" % LABEL_DESC[str(fields.get("Label"))])
        else:
            bad = [c["item"] for c in checks if not c["ok"]]
            out.append("  检出隐式标识，但存在不合规项：%s。" % "、".join(bad))
    elif v == "informal":
        out.append("  检出 AIGC 相关元数据，但不在标准规定位置，不能直接认定为合规标识，"
                   "需固证后人工核验。")
    else:
        out.append("  未检出 GB 45438-2025 要求的文件元数据隐式标识。")
        if c2pa:
            out.append("  但检出 C2PA 内容凭证%s，属国际通行的另一条溯源体系。"
                       % ("（生成工具：%s）" % c2pa["generator"] if c2pa["generator"] else ""))
            out.append("  可作为「该内容由 AI 生成」的旁证，但不能直接套用 GB 45438 的合规判定。")
        out.append("  注意：本工具只覆盖元数据类标识，未检出不能推论「非 AI 生成」。")
        out.append("  建议下一步：")
        out.append("    1) 目视检查显式标识（GB 45438-2025 第 5 章）——文本首尾/图片边角"
                   "「AI生成」水印、音频「短长 短短」节奏、视频起始画面≥2s 角标；")
        out.append("    2) 检查内容隐式标识（数字水印），元数据易被平台剥离，水印通常保留；")
        out.append("    3) 结合 TC260-PG-202512A 的算法检测（频域/伪影/时序一致性）；")
        out.append("    4) 核查文件获取渠道：经社交平台二次转存通常会清除元数据。")

    if dump and info.get("dump"):
        sec("元数据/容器结构")
        for line in info["dump"][:200]:
            out.append("  " + line)
        if len(info["dump"]) > 200:
            out.append("  …（共 %d 项）" % len(info["dump"]))
    out.append("")
    return "\n".join(out)

def to_json(info, checks, fields, mode, notes, sd_lines):
    v, vtext = verdict_of(info)
    return {
        "file": info["file"],
        "name": info["name"],
        "size": info["size"],
        "format": info["kind"],
        "format_desc": info["kind_desc"],
        "verdict": v,
        "verdict_text": vtext,
        "compliant": bool(checks) and all(c["ok"] for c in checks) if v == "found" else False,
        "hits": [h.to_dict() for h in info["hits"]],
        "storage_mode": mode,
        "fields": fields,
        "label_meaning": LABEL_DESC.get(str((fields or {}).get("Label", "")), ""),
        "provider_codes": {
            k: decode_provider_code((fields or {}).get(k) or "")
            for k in ("ContentProducer", "ContentPropagator")
        },
        "checks": checks,
        "notes": notes,
        "security_data": sd_lines,
        "c2pa": info.get("c2pa"),
        "tool_version": __version__,
    }


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------
def collect(paths, recursive):
    files = []
    for p in paths:
        if os.path.isdir(p):
            if recursive:
                for root, _dirs, names in os.walk(p):
                    for n in names:
                        files.append(os.path.join(root, n))
            else:
                for n in sorted(os.listdir(p)):
                    fp = os.path.join(p, n)
                    if os.path.isfile(fp):
                        files.append(fp)
        elif os.path.isfile(p):
            files.append(p)
        else:
            print("跳过（不存在）: %s" % p, file=sys.stderr)
    return sorted(files)


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="GB 45438-2025 文件元数据隐式标识（AIGC）检测器",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="示例:\n"
               "  python aigc_check.py a.png                    单文件详细报告\n"
               "  python aigc_check.py 样本目录 -r               递归批量\n"
               "  python aigc_check.py 样本目录 --summary        汇总表\n"
               "  python aigc_check.py a.mp4 --json > out.json  机器可读\n"
               "  python aigc_check.py a.docx --dump            附容器结构")
    ap.add_argument("paths", nargs="+", help="待检文件或目录")
    ap.add_argument("-r", "--recursive", action="store_true", help="递归子目录")
    ap.add_argument("--json", action="store_true", help="输出 JSON（机器可读）")
    ap.add_argument("--dump", action="store_true", help="附带容器元数据结构")
    ap.add_argument("--summary", action="store_true", help="只输出汇总表")
    ap.add_argument("-o", "--output", help="报告写入文件")
    ap.add_argument("-v", "--version", action="version", version="aigc_check " + __version__)
    args = ap.parse_args(argv)

    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

    files = collect(args.paths, args.recursive)
    if not files:
        print("没有可检测的文件。", file=sys.stderr)
        return 2

    results, blocks = [], []
    for fp in files:
        try:
            info = analyze_file(fp, dump=args.dump)
        except Exception as e:
            blocks.append("%s\n读取失败: %s\n" % (fp, e))
            results.append({"file": fp, "verdict": "error", "error": str(e)})
            continue
        fields, mode, notes = None, None, []
        std = [h for h in info["hits"] if h.standard] or info["hits"]
        if std:
            fields, mode, notes = parse_ident(std[0].raw)
        checks, sd = validate_only(fields)
        sd_lines = summarize_sd(sd) if sd else []
        if args.json:
            results.append(to_json(info, checks, fields, mode, notes, sd_lines))
        else:
            blocks.append(render(info, checks, fields, mode, notes, sd_lines, args.dump))
            cp = info.get("c2pa")
            results.append({"_brief": (info["name"], verdict_of(info)[0],
                                       (fields or {}).get("Label"),
                                       (cp.get("generator") or "C2PA") if cp else "")})

    if args.json:
        text = json.dumps(results if len(results) > 1 else results[0],
                          ensure_ascii=False, indent=2)
    elif args.summary:
        lines = ["%-42s %-8s %-6s %s" % ("文件", "GB45438", "Label", "C2PA 旁证"),
                 "-" * 96]
        for r in results:
            if "_brief" in r:
                n, v, lab, cp = r["_brief"]
                lines.append("%-42s %-8s %-6s %s" % (
                    n[:40],
                    {"found": "检出", "informal": "疑似", "not_found": "未检出"}.get(v, v),
                    lab or "-", cp[:40] or "-"))
        text = "\n".join(lines) + "\n"
    else:
        text = "\n".join(blocks)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(text)
        print("报告已写入 %s" % args.output)
    else:
        print(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
