//! EVTX binary XML (MS-EVEN6 BinXml) parser and renderer.
//!
//! Token coverage: EOF (0x00), OpenStartElement (0x01/0x41), CloseStartElement (0x02),
//! CloseEmptyElement (0x03), EndElement (0x04), Value (0x05/0x45), Attribute (0x06/0x46),
//! CDATA (0x07/0x47), CharRef (0x08/0x48), EntityRef (0x09/0x49), PITarget (0x0a),
//! PIData (0x0b), TemplateInstance (0x0c), NormalSubstitution (0x0d),
//! OptionalSubstitution (0x0e), FragmentHeader (0x0f). Template definitions are cached per
//! chunk by their chunk offset.
use crate::error::{ParseError, Result};
use crate::shellitems::decode_ansi;
use crate::util::{need, u16_at, u32_at, u64_at, u8_at, utf16le};
use std::cell::RefCell;
use std::collections::BTreeMap;
use std::rc::Rc;
use veritas_timeline::filetime_to_ns;

/// Maximum nesting of template instances / nested BinXml values.
pub const MAX_TEMPLATE_DEPTH: usize = 64;
/// Maximum element nesting depth inside one fragment.
const MAX_ELEMENT_DEPTH: usize = 256;
/// Maximum substitution values per template instance.
const MAX_VALUES: usize = 4096;
/// Maximum token count per record (guards against pathological inputs).
const MAX_TOKENS: usize = 1_000_000;

#[derive(Debug, Clone)]
pub enum Node {
    Element(Element),
    Text(String),
    CData(String),
    CharRef(u16),
    EntityRef(String),
    Pi(String, String),
    Subst { id: u16, vtype: u8, optional: bool },
    Template(TemplateInstance),
}

#[derive(Debug, Clone)]
pub struct Element {
    pub name: String,
    pub attrs: Vec<(String, Vec<Node>)>,
    pub children: Vec<Node>,
}

#[derive(Debug, Clone)]
pub struct TemplateInstance {
    pub def: Rc<Vec<Node>>,
    pub values: Vec<BinValue>,
}

#[derive(Debug, Clone)]
pub struct BinValue {
    pub vtype: u8,
    /// Chunk-relative offset of the value data.
    pub offset: usize,
    pub size: usize,
}

/// Rendered XML tree.
#[derive(Debug, Clone, PartialEq)]
pub enum XNode {
    Elem(XElem),
    Text(String),
    CData(String),
    Pi(String, String),
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct XElem {
    pub name: String,
    pub attrs: Vec<(String, String)>,
    pub children: Vec<XNode>,
}

impl XElem {
    pub fn child(&self, name: &str) -> Option<&XElem> {
        self.children.iter().find_map(|c| match c {
            XNode::Elem(e) if e.name == name => Some(e),
            _ => None,
        })
    }
    pub fn elems(&self) -> impl Iterator<Item = &XElem> {
        self.children.iter().filter_map(|c| match c {
            XNode::Elem(e) => Some(e),
            _ => None,
        })
    }
    pub fn attr(&self, name: &str) -> Option<&str> {
        self.attrs.iter().find(|(k, _)| k == name).map(|(_, v)| v.as_str())
    }
    /// Concatenated text content (direct text children only).
    pub fn text(&self) -> String {
        let mut s = String::new();
        for c in &self.children {
            match c {
                XNode::Text(t) | XNode::CData(t) => s.push_str(t),
                _ => {}
            }
        }
        s
    }
    pub fn has_elem_children(&self) -> bool {
        self.children.iter().any(|c| matches!(c, XNode::Elem(_)))
    }
}

/// Parsing context for one chunk.
pub struct Chunk<'a> {
    pub data: &'a [u8],
    templates: RefCell<BTreeMap<usize, Rc<Vec<Node>>>>,
    tokens: RefCell<usize>,
}

impl<'a> Chunk<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Chunk { data, templates: RefCell::new(BTreeMap::new()), tokens: RefCell::new(0) }
    }

    pub fn template_count(&self) -> usize {
        self.templates.borrow().len()
    }

    fn tick(&self) -> Result<()> {
        let mut t = self.tokens.borrow_mut();
        *t += 1;
        if *t > MAX_TOKENS {
            return Err(ParseError::Limit("binary XML token budget exceeded".into()));
        }
        Ok(())
    }

    pub fn reset_budget(&self) {
        *self.tokens.borrow_mut() = 0;
    }

    fn name_at(&self, name_off: usize, p: &mut usize) -> Result<String> {
        let d = self.data;
        let len = u16_at(d, name_off + 6)? as usize;
        let s = utf16le(need(d, name_off + 8, len * 2)?, false);
        if name_off == *p {
            // Name stored inline right here: skip next-offset(4) hash(2) len(2) chars NUL(2).
            *p = name_off + 8 + len * 2 + 2;
        }
        Ok(s)
    }

    /// Parse a fragment (sequence of top-level tokens) starting at chunk offset `p`.
    pub fn parse_fragment(&self, mut p: usize, end: usize, depth: usize) -> Result<(Vec<Node>, usize)> {
        if depth > MAX_TEMPLATE_DEPTH {
            return Err(ParseError::Limit("binary XML template nesting exceeds 64".into()));
        }
        let d = self.data;
        let mut out = Vec::new();
        while p < end {
            self.tick()?;
            let tok = u8_at(d, p)?;
            match tok {
                0x00 => {
                    p += 1;
                    break;
                }
                0x0f => p += 4,
                0x01 | 0x41 => {
                    let (e, np) = self.parse_element(p, depth, 0)?;
                    out.push(Node::Element(e));
                    p = np;
                }
                0x0c => {
                    let (t, np) = self.parse_template_instance(p, depth)?;
                    out.push(Node::Template(t));
                    p = np;
                }
                0x05 | 0x45 | 0x0d | 0x0e | 0x07 | 0x47 | 0x08 | 0x48 | 0x09 | 0x49 | 0x0a => {
                    let (n, np) = self.parse_content_token(p, depth)?;
                    out.push(n);
                    p = np;
                }
                t => return Err(ParseError::Invalid { offset: p, reason: format!("unexpected binary XML token 0x{t:02x} in fragment") }),
            }
        }
        Ok((out, p))
    }

    fn parse_template_instance(&self, mut p: usize, depth: usize) -> Result<(TemplateInstance, usize)> {
        let d = self.data;
        p += 2; // token + unknown byte
        let _template_id = u32_at(d, p)?;
        let def_off = u32_at(d, p + 4)? as usize;
        p += 8;
        let cached = self.templates.borrow().get(&def_off).cloned();
        let def = match cached {
            Some(t) => {
                if def_off == p {
                    let size = u32_at(d, p + 20)? as usize;
                    p = p + 24 + size;
                }
                t
            }
            None => {
                let size = u32_at(d, def_off + 20)? as usize;
                let start = def_off + 24;
                need(d, start, size)?;
                let (nodes, _) = self.parse_fragment(start, start + size, depth + 1)?;
                let rc = Rc::new(nodes);
                self.templates.borrow_mut().insert(def_off, rc.clone());
                if def_off == p {
                    p = start + size;
                }
                rc
            }
        };
        let count = u32_at(d, p)? as usize;
        if count > MAX_VALUES {
            return Err(ParseError::Limit(format!("{count} substitution values")));
        }
        p += 4;
        let desc = need(d, p, count * 4)?;
        p += count * 4;
        let mut values = Vec::with_capacity(count);
        for i in 0..count {
            let size = u16::from_le_bytes([desc[i * 4], desc[i * 4 + 1]]) as usize;
            let vtype = desc[i * 4 + 2];
            need(d, p, size)?;
            values.push(BinValue { vtype, offset: p, size });
            p += size;
        }
        Ok((TemplateInstance { def, values }, p))
    }

    fn parse_element(&self, mut p: usize, depth: usize, edepth: usize) -> Result<(Element, usize)> {
        if edepth > MAX_ELEMENT_DEPTH {
            return Err(ParseError::Limit("binary XML element nesting too deep".into()));
        }
        let d = self.data;
        let tok = u8_at(d, p)?;
        let has_attrs = tok & 0x40 != 0;
        p += 1 + 2; // token + dependency identifier
        let _size = u32_at(d, p)?;
        let name_off = u32_at(d, p + 4)? as usize;
        p += 8;
        let name = self.name_at(name_off, &mut p)?;
        if has_attrs {
            p += 4; // attribute list size (follows an inline name)
        }
        let mut el = Element { name, attrs: Vec::new(), children: Vec::new() };
        if has_attrs {
            loop {
                self.tick()?;
                let t = u8_at(d, p)?;
                if t & 0xbf != 0x06 {
                    break;
                }
                p += 1;
                let aoff = u32_at(d, p)? as usize;
                p += 4;
                let aname = self.name_at(aoff, &mut p)?;
                let mut val = Vec::new();
                loop {
                    let vt = u8_at(d, p)?;
                    if !matches!(vt, 0x05 | 0x45 | 0x0d | 0x0e | 0x08 | 0x48 | 0x09 | 0x49 | 0x07 | 0x47) {
                        break;
                    }
                    let (n, np) = self.parse_content_token(p, depth)?;
                    val.push(n);
                    p = np;
                }
                el.attrs.push((aname, val));
            }
        }
        let close = u8_at(d, p)?;
        p += 1;
        match close {
            0x03 => return Ok((el, p)),
            0x02 => {}
            t => return Err(ParseError::Invalid { offset: p - 1, reason: format!("expected close start element, got 0x{t:02x}") }),
        }
        loop {
            self.tick()?;
            let t = u8_at(d, p)?;
            match t {
                0x04 => {
                    p += 1;
                    break;
                }
                0x01 | 0x41 => {
                    let (c, np) = self.parse_element(p, depth, edepth + 1)?;
                    el.children.push(Node::Element(c));
                    p = np;
                }
                0x0c => {
                    let (ti, np) = self.parse_template_instance(p, depth + 1)?;
                    el.children.push(Node::Template(ti));
                    p = np;
                }
                0x05 | 0x45 | 0x0d | 0x0e | 0x07 | 0x47 | 0x08 | 0x48 | 0x09 | 0x49 | 0x0a => {
                    let (n, np) = self.parse_content_token(p, depth)?;
                    el.children.push(n);
                    p = np;
                }
                t => return Err(ParseError::Invalid { offset: p, reason: format!("unexpected token 0x{t:02x} in element content") }),
            }
        }
        Ok((el, p))
    }

    fn parse_content_token(&self, mut p: usize, _depth: usize) -> Result<(Node, usize)> {
        let d = self.data;
        let t = u8_at(d, p)?;
        p += 1;
        let n = match t & 0xbf {
            0x05 => {
                let vtype = u8_at(d, p)?;
                p += 1;
                match vtype {
                    0x01 => {
                        let n = u16_at(d, p)? as usize;
                        let s = utf16le(need(d, p + 2, n * 2)?, false);
                        p += 2 + n * 2;
                        Node::Text(s)
                    }
                    0x02 => {
                        let n = u16_at(d, p)? as usize;
                        let s = decode_ansi(need(d, p + 2, n)?);
                        p += 2 + n;
                        Node::Text(s)
                    }
                    v => return Err(ParseError::Unsupported(format!("value text type 0x{v:02x}"))),
                }
            }
            0x0d | 0x0e => {
                let id = u16_at(d, p)?;
                let vtype = u8_at(d, p + 2)?;
                p += 3;
                Node::Subst { id, vtype, optional: t == 0x0e }
            }
            0x07 => {
                let n = u16_at(d, p)? as usize;
                let s = utf16le(need(d, p + 2, n * 2)?, false);
                p += 2 + n * 2;
                Node::CData(s)
            }
            0x08 => {
                let v = u16_at(d, p)?;
                p += 2;
                Node::CharRef(v)
            }
            0x09 => {
                let off = u32_at(d, p)? as usize;
                p += 4;
                Node::EntityRef(self.name_at(off, &mut p)?)
            }
            0x0a => {
                let off = u32_at(d, p)? as usize;
                p += 4;
                let target = self.name_at(off, &mut p)?;
                let mut data = String::new();
                if u8_at(d, p).ok() == Some(0x0b) {
                    let n = u16_at(d, p + 1)? as usize;
                    data = utf16le(need(d, p + 3, n * 2)?, false);
                    p += 3 + n * 2;
                }
                Node::Pi(target, data)
            }
            _ => return Err(ParseError::Invalid { offset: p - 1, reason: format!("token 0x{t:02x} is not content") }),
        };
        Ok((n, p))
    }

    // ------------------------------------------------------------ resolution

    /// Resolve parsed nodes into an XML tree, applying template substitutions.
    pub fn resolve(&self, nodes: &[Node], values: &[BinValue], depth: usize) -> Result<Vec<XNode>> {
        if depth > MAX_TEMPLATE_DEPTH {
            return Err(ParseError::Limit("binary XML template nesting exceeds 64".into()));
        }
        let mut out: Vec<XNode> = Vec::new();
        for n in nodes {
            self.tick()?;
            match n {
                Node::Element(e) => {
                    // An element whose sole content is an array substitution is repeated once
                    // per array item (libfwevt behaviour).
                    if let [Node::Subst { id, .. }] = e.children.as_slice() {
                        if let Some(v) = values.get(*id as usize) {
                            if v.vtype & 0x80 != 0 && v.size > 0 {
                                for item in array_items(self.data, v) {
                                    if let Some(mut x) = self.resolve_element(&Element { name: e.name.clone(), attrs: e.attrs.clone(), children: vec![] }, values, depth)? {
                                        if !is_blank_lines(&item) {
                                            x.children.push(XNode::Text(item));
                                        }
                                        out.push(XNode::Elem(x));
                                    }
                                }
                                continue;
                            }
                        }
                    }
                    if let Some(x) = self.resolve_element(e, values, depth)? {
                        out.push(XNode::Elem(x));
                    }
                }
                Node::Template(t) => {
                    let r = self.resolve(&t.def, &t.values, depth + 1)?;
                    out.extend(r);
                }
                other => {
                    for x in self.resolve_content(other, values, depth)? {
                        push_merge(&mut out, x);
                    }
                }
            }
        }
        Ok(out)
    }

    fn resolve_content(&self, n: &Node, values: &[BinValue], depth: usize) -> Result<Vec<XNode>> {
        Ok(match n {
            Node::Text(s) => vec![XNode::Text(s.clone())],
            Node::CData(s) => vec![XNode::CData(s.clone())],
            Node::CharRef(c) => vec![XNode::Text(char::from_u32(*c as u32).map(|c| c.to_string()).unwrap_or_default())],
            Node::EntityRef(name) => vec![XNode::Text(match name.as_str() {
                "amp" => "&".into(),
                "lt" => "<".into(),
                "gt" => ">".into(),
                "quot" => "\"".into(),
                "apos" => "'".into(),
                other => format!("&{other};"),
            })],
            Node::Pi(t, d) => vec![XNode::Pi(t.clone(), d.clone())],
            Node::Subst { id, .. } => {
                let Some(v) = values.get(*id as usize) else { return Ok(vec![]) };
                if v.vtype == 0x21 {
                    if v.size == 0 {
                        return Ok(vec![]);
                    }
                    let (nodes, _) = self.parse_fragment(v.offset, v.offset + v.size, depth + 1)?;
                    self.resolve(&nodes, &[], depth + 1)?
                } else if v.vtype == 0 || v.size == 0 {
                    vec![]
                } else {
                    let s = value_to_string(self.data, v);
                    // libfwevt renders values consisting only of line breaks as empty.
                    if is_blank_lines(&s) {
                        vec![]
                    } else {
                        vec![XNode::Text(s)]
                    }
                }
            }
            Node::Element(_) | Node::Template(_) => vec![],
        })
    }

    fn is_empty_value(&self, n: &Node, values: &[BinValue]) -> bool {
        match n {
            Node::Subst { id, .. } => match values.get(*id as usize) {
                None => true,
                Some(v) => v.vtype == 0 || v.size == 0,
            },
            _ => false,
        }
    }

    fn resolve_element(&self, e: &Element, values: &[BinValue], depth: usize) -> Result<Option<XElem>> {
        // An element whose only content is optional substitutions that are all empty is dropped.
        let only_optional = !e.children.is_empty() && e.children.iter().all(|c| matches!(c, Node::Subst { optional: true, .. }));
        if only_optional && e.children.iter().all(|c| self.is_empty_value(c, values)) {
            return Ok(None);
        }
        let mut x = XElem { name: e.name.clone(), attrs: Vec::new(), children: Vec::new() };
        for (an, av) in &e.attrs {
            let all_opt_empty = !av.is_empty() && av.iter().all(|c| matches!(c, Node::Subst { optional: true, .. }) && self.is_empty_value(c, values));
            if all_opt_empty {
                continue;
            }
            let mut s = String::new();
            for c in av {
                for r in self.resolve_content(c, values, depth)? {
                    match r {
                        XNode::Text(t) | XNode::CData(t) => s.push_str(&t),
                        XNode::Elem(el) => s.push_str(&el.text()),
                        XNode::Pi(..) => {}
                    }
                }
            }
            x.attrs.push((an.clone(), s));
        }
        x.children = self.resolve(&e.children, values, depth)?;
        Ok(Some(x))
    }
}

/// Empty, or only CR/LF characters (rendered as an empty element by libfwevt).
fn is_blank_lines(s: &str) -> bool {
    s.chars().all(|c| c == '\n' || c == '\r')
}

fn push_merge(out: &mut Vec<XNode>, x: XNode) {
    if let (Some(XNode::Text(prev)), XNode::Text(t)) = (out.last_mut(), &x) {
        prev.push_str(t);
        return;
    }
    out.push(x);
}

// ---------------------------------------------------------------- values

fn fmt_filetime(ft: u64) -> String {
    match filetime_to_ns(ft) {
        Some(ns) => {
            let secs = ns.div_euclid(1_000_000_000);
            let frac = ns.rem_euclid(1_000_000_000);
            match chrono::DateTime::from_timestamp(secs, 0) {
                Some(dt) => format!("{}.{:09}Z", dt.format("%Y-%m-%dT%H:%M:%S"), frac),
                None => format!("0x{ft:016x}"),
            }
        }
        None => if ft == 0 { "1601-01-01T00:00:00.000000000Z".into() } else { format!("0x{ft:016x}") },
    }
}

pub fn sid_string(b: &[u8]) -> Option<String> {
    if b.len() < 8 {
        return None;
    }
    let rev = b[0];
    let n = b[1] as usize;
    if b.len() < 8 + n * 4 {
        return None;
    }
    let auth = b[2..8].iter().fold(0u64, |a, &x| (a << 8) | x as u64);
    let mut s = format!("S-{rev}-{auth}");
    for i in 0..n {
        let o = 8 + i * 4;
        s.push_str(&format!("-{}", u32::from_le_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]])));
    }
    Some(s)
}

fn guid_upper(b: &[u8]) -> String {
    crate::shellitems::guid_string(b).map(|g| format!("{{{}}}", g.to_ascii_uppercase())).unwrap_or_default()
}

fn scalar(vtype: u8, b: &[u8]) -> String {
    let u = |n: usize| -> u64 { b.iter().take(n).enumerate().fold(0u64, |a, (i, &x)| a | ((x as u64) << (8 * i))) };
    match vtype {
        0x01 => utf16le(b, true),
        0x02 => decode_ansi(&b[..b.iter().position(|&c| c == 0).unwrap_or(b.len())]),
        0x03 => (u(1) as u8 as i8).to_string(),
        0x04 => u(1).to_string(),
        0x05 => (u(2) as u16 as i16).to_string(),
        0x06 => u(2).to_string(),
        0x07 => (u(4) as u32 as i32).to_string(),
        0x08 => u(4).to_string(),
        0x09 => (u(8) as i64).to_string(),
        0x0a => u(8).to_string(),
        0x0b => {
            let f = f32::from_bits(u(4) as u32);
            format!("{f}")
        }
        0x0c => {
            let f = f64::from_bits(u(8));
            format!("{f}")
        }
        0x0d => if u(4) != 0 { "true".into() } else { "false".into() },
        0x0e => crate::util::hex_upper(b),
        0x0f => guid_upper(b),
        0x10 => if b.len() >= 8 { format!("0x{:016x}", u(8)) } else { format!("0x{:08x}", u(4)) },
        0x11 => fmt_filetime(u(8)),
        0x12 => {
            if b.len() < 16 {
                return String::new();
            }
            let w = |i: usize| u16::from_le_bytes([b[i * 2], b[i * 2 + 1]]);
            format!("{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:09}Z", w(0), w(1), w(3), w(4), w(5), w(6), w(7) as u32 * 1_000_000)
        }
        0x13 => sid_string(b).unwrap_or_default(),
        0x14 => format!("0x{:08x}", u(4)),
        0x15 => format!("0x{:016x}", u(8)),
        _ => crate::util::hex_upper(b),
    }
}

fn elem_size(vtype: u8) -> usize {
    match vtype {
        0x03 | 0x04 => 1,
        0x05 | 0x06 => 2,
        0x07 | 0x08 | 0x0b | 0x0d | 0x14 => 4,
        0x09 | 0x0a | 0x0c | 0x11 | 0x15 | 0x10 => 8,
        0x0f | 0x12 => 16,
        _ => 0,
    }
}

/// Render a substitution value as text (libfwevt conventions). Arrays are joined with ", ".
pub fn value_to_string(chunk: &[u8], v: &BinValue) -> String {
    if v.vtype & 0x80 != 0 {
        return array_items(chunk, v).join(", ");
    }
    let b = match need(chunk, v.offset, v.size) {
        Ok(b) => b,
        Err(_) => return String::new(),
    };
    if v.vtype == 0x10 {
        return if v.size >= 8 { format!("0x{:016x}", u64_at(b, 0).unwrap_or(0)) } else { format!("0x{:08x}", u32_at(b, 0).unwrap_or(0)) };
    }
    scalar(v.vtype, b)
}

/// Items of an array value (type | 0x80).
pub fn array_items(chunk: &[u8], v: &BinValue) -> Vec<String> {
    let b = match need(chunk, v.offset, v.size) {
        Ok(b) => b,
        Err(_) => return Vec::new(),
    };
    {
        let base = v.vtype & 0x7f;
        let parts: Vec<String> = match base {
            0x01 => {
                let s = utf16le(b, false);
                let mut v: Vec<String> = s.split('\0').map(|x| x.to_string()).collect();
                if v.last().map(|x| x.is_empty()).unwrap_or(false) {
                    v.pop();
                }
                v
            }
            0x02 => b.split(|&c| c == 0).filter(|s| !s.is_empty()).map(decode_ansi).collect(),
            0x13 => {
                let mut out = Vec::new();
                let mut o = 0;
                while o + 8 <= b.len() {
                    let n = b[o + 1] as usize;
                    let len = 8 + n * 4;
                    if o + len > b.len() {
                        break;
                    }
                    out.push(sid_string(&b[o..o + len]).unwrap_or_default());
                    o += len;
                }
                out
            }
            t => {
                let es = elem_size(t);
                if es == 0 {
                    vec![crate::util::hex_upper(b)]
                } else {
                    b.chunks_exact(es).map(|c| scalar(t, c)).collect()
                }
            }
        };
        parts
    }
}

// ---------------------------------------------------------------- rendering

fn esc_text(s: &str, out: &mut String) {
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            _ => out.push(c),
        }
    }
}

fn esc_attr(s: &str, out: &mut String) {
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            _ => out.push(c),
        }
    }
}

/// Render an XML tree the way libevtx's `xml_string` does (two-space indentation).
pub fn render(nodes: &[XNode]) -> String {
    let mut out = String::new();
    for n in nodes {
        render_node(n, 0, &mut out);
    }
    out
}

fn render_node(n: &XNode, depth: usize, out: &mut String) {
    let ind = "  ".repeat(depth);
    match n {
        XNode::Elem(e) => {
            out.push_str(&ind);
            out.push('<');
            out.push_str(&e.name);
            for (k, v) in &e.attrs {
                out.push(' ');
                out.push_str(k);
                out.push_str("=\"");
                esc_attr(v, out);
                out.push('"');
            }
            let has_content = e.children.iter().any(|c| !matches!(c, XNode::Text(t) if t.is_empty()));
            if !has_content {
                out.push_str("/>\n");
            } else if !e.has_elem_children() && !e.children.iter().any(|c| matches!(c, XNode::Pi(..))) {
                out.push('>');
                for c in &e.children {
                    match c {
                        XNode::Text(t) => esc_text(t, out),
                        XNode::CData(t) => {
                            out.push_str("<![CDATA[");
                            out.push_str(t);
                            out.push_str("]]>");
                        }
                        _ => {}
                    }
                }
                out.push_str("</");
                out.push_str(&e.name);
                out.push_str(">\n");
            } else {
                out.push_str(">\n");
                for c in &e.children {
                    render_node(c, depth + 1, out);
                }
                out.push_str(&ind);
                out.push_str("</");
                out.push_str(&e.name);
                out.push_str(">\n");
            }
        }
        XNode::Text(t) => {
            if !t.trim().is_empty() {
                out.push_str(&ind);
                esc_text(t, out);
                out.push('\n');
            }
        }
        XNode::CData(t) => {
            out.push_str(&ind);
            out.push_str("<![CDATA[");
            out.push_str(t);
            out.push_str("]]>\n");
        }
        XNode::Pi(t, d) => {
            out.push_str(&ind);
            out.push_str(&format!("<?{t} {d}?>\n"));
        }
    }
}
