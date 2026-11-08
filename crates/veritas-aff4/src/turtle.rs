//! A small, bounded RDF 1.1 Turtle parser: enough for `information.turtle` as written by pyaff4,
//! Evimetry and this crate.
//!
//! Supported: `@prefix` / `@base` and SPARQL-style `PREFIX` / `BASE`, IRI references (relative
//! IRIs are appended to the base), prefixed names (with `\` and `%xx` in local names), `a`,
//! predicate-object lists with `;` and `,`, blank node labels, blank node property lists
//! (`[ ... ]`), collections (`( ... )`, expanded to `rdf:first` / `rdf:rest`), short and long
//! string literals in both quote styles with escapes, language tags, `^^` datatypes, integers,
//! decimals, doubles and booleans, and `#` comments.
//!
//! Limits: at most [`MAX_TRIPLES`] triples and [`MAX_DEPTH`] levels of `[`/`(` nesting; errors
//! carry the byte offset at which parsing stopped.

use crate::{Aff4Error, Result, RDF_TYPE, XSD};
use std::collections::HashMap;

pub const MAX_TRIPLES: usize = 4_000_000;
pub const MAX_DEPTH: usize = 64;

const RDF: &str = "http://www.w3.org/1999/02/22-rdf-syntax-ns#";

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Literal {
    pub value: String,
    pub datatype: Option<String>,
    pub lang: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Term {
    Iri(String),
    Blank(String),
    Literal(Literal),
}

impl Term {
    fn key(&self) -> String {
        match self {
            Term::Iri(s) => s.clone(),
            Term::Blank(b) => format!("_:{}", b),
            Term::Literal(l) => format!("\"{}\"", l.value),
        }
    }
    pub fn as_iri(&self) -> Option<&str> {
        match self {
            Term::Iri(s) => Some(s),
            _ => None,
        }
    }
    pub fn as_literal(&self) -> Option<&Literal> {
        match self {
            Term::Literal(l) => Some(l),
            _ => None,
        }
    }
    /// Lexical value of a literal, or the IRI.
    pub fn lexical(&self) -> &str {
        match self {
            Term::Iri(s) | Term::Blank(s) => s,
            Term::Literal(l) => &l.value,
        }
    }
    /// Integer value of a numeric literal (any xsd integer type or untyped digits).
    pub fn as_u64(&self) -> Option<u64> {
        self.as_literal()?.value.trim().parse::<u64>().ok()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Triple {
    pub s: Term,
    pub p: String,
    pub o: Term,
}

/// Parsed triples with a subject index.
#[derive(Debug, Default, Clone)]
pub struct Graph {
    pub triples: Vec<Triple>,
    by_subject: HashMap<String, Vec<usize>>,
}

impl Graph {
    fn index(&mut self) {
        self.by_subject.clear();
        for (i, t) in self.triples.iter().enumerate() {
            self.by_subject.entry(t.s.key()).or_default().push(i);
        }
    }

    /// Merge another graph (e.g. a second Turtle document appended by pyaff4).
    pub fn extend(&mut self, other: Graph) {
        self.triples.extend(other.triples);
        self.index();
    }

    pub fn len(&self) -> usize {
        self.triples.len()
    }
    pub fn is_empty(&self) -> bool {
        self.triples.is_empty()
    }

    /// Objects of `(subject, predicate)` in document order.
    pub fn objects<'a>(&'a self, subject: &str, predicate: &str) -> Vec<&'a Term> {
        self.by_subject
            .get(subject)
            .map(|v| {
                v.iter()
                    .filter_map(|&i| self.triples.get(i))
                    .filter(|t| t.p == predicate)
                    .map(|t| &t.o)
                    .collect()
            })
            .unwrap_or_default()
    }

    pub fn object<'a>(&'a self, subject: &str, predicate: &str) -> Option<&'a Term> {
        self.objects(subject, predicate).into_iter().next()
    }

    pub fn has_type(&self, subject: &str, ty: &str) -> bool {
        self.objects(subject, RDF_TYPE)
            .iter()
            .any(|t| t.as_iri() == Some(ty))
    }

    /// IRI subjects with `rdf:type ty`, unique, in document order.
    pub fn subjects_of_type(&self, ty: &str) -> Vec<String> {
        let mut out: Vec<String> = Vec::new();
        for t in &self.triples {
            if t.p == RDF_TYPE && t.o.as_iri() == Some(ty) {
                if let Term::Iri(s) = &t.s {
                    if !out.contains(s) {
                        out.push(s.clone());
                    }
                }
            }
        }
        out
    }
}

/// Parse a Turtle document.
pub fn parse(input: &str) -> Result<Graph> {
    let mut p = Parser {
        s: input.as_bytes(),
        i: 0,
        prefixes: HashMap::new(),
        base: String::new(),
        triples: Vec::new(),
        bnodes: 0,
        depth: 0,
    };
    p.document()?;
    let mut g = Graph {
        triples: p.triples,
        by_subject: HashMap::new(),
    };
    g.index();
    Ok(g)
}

struct Parser<'a> {
    s: &'a [u8],
    i: usize,
    prefixes: HashMap<String, String>,
    base: String,
    triples: Vec<Triple>,
    bnodes: u64,
    depth: usize,
}

fn is_name_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_' || b == b'-' || b >= 0x80
}

impl<'a> Parser<'a> {
    fn err<T>(&self, msg: &str) -> Result<T> {
        Err(Aff4Error::Turtle(format!("{} at byte {}", msg, self.i)))
    }

    fn peek(&self) -> Option<u8> {
        self.s.get(self.i).copied()
    }

    fn peek_at(&self, n: usize) -> Option<u8> {
        self.s.get(self.i + n).copied()
    }

    fn starts_with(&self, lit: &[u8]) -> bool {
        self.s.get(self.i..self.i + lit.len()) == Some(lit)
    }

    fn starts_with_keyword_ci(&self, kw: &str) -> bool {
        let n = kw.len();
        match self.s.get(self.i..self.i + n) {
            Some(b) if b.eq_ignore_ascii_case(kw.as_bytes()) => {
                !matches!(self.s.get(self.i + n), Some(&c) if is_name_byte(c) || c == b':')
            }
            _ => false,
        }
    }

    fn ws(&mut self) {
        while let Some(c) = self.peek() {
            if c.is_ascii_whitespace() {
                self.i += 1;
            } else if c == b'#' {
                while let Some(c) = self.peek() {
                    self.i += 1;
                    if c == b'\n' || c == b'\r' {
                        break;
                    }
                }
            } else {
                break;
            }
        }
    }

    fn expect(&mut self, c: u8) -> Result<()> {
        self.ws();
        if self.peek() == Some(c) {
            self.i += 1;
            Ok(())
        } else {
            self.err(&format!("expected '{}'", c as char))
        }
    }

    fn push(&mut self, s: Term, p: String, o: Term) -> Result<()> {
        if self.triples.len() >= MAX_TRIPLES {
            return Err(Aff4Error::Limit(format!(
                "more than {} triples",
                MAX_TRIPLES
            )));
        }
        self.triples.push(Triple { s, p, o });
        Ok(())
    }

    fn new_bnode(&mut self) -> Term {
        self.bnodes += 1;
        Term::Blank(format!("genid{}", self.bnodes))
    }

    fn document(&mut self) -> Result<()> {
        loop {
            self.ws();
            if self.peek().is_none() {
                return Ok(());
            }
            if self.starts_with(b"@prefix") {
                self.i += 7;
                self.prefix_decl()?;
                self.expect(b'.')?;
            } else if self.starts_with(b"@base") {
                self.i += 5;
                self.ws();
                self.base = self.iri_ref()?;
                self.expect(b'.')?;
            } else if self.starts_with_keyword_ci("PREFIX") {
                self.i += 6;
                self.prefix_decl()?;
            } else if self.starts_with_keyword_ci("BASE") {
                self.i += 4;
                self.ws();
                self.base = self.iri_ref()?;
            } else {
                self.statement()?;
            }
        }
    }

    fn prefix_decl(&mut self) -> Result<()> {
        self.ws();
        let start = self.i;
        while let Some(c) = self.peek() {
            if is_name_byte(c) || c == b'.' {
                self.i += 1;
            } else {
                break;
            }
        }
        let name = String::from_utf8_lossy(&self.s[start..self.i]).into_owned();
        if self.peek() != Some(b':') {
            return self.err("expected ':' in prefix declaration");
        }
        self.i += 1;
        self.ws();
        let iri = self.iri_ref()?;
        self.prefixes.insert(name, iri);
        Ok(())
    }

    fn statement(&mut self) -> Result<()> {
        self.ws();
        let (subject, was_property_list) = match self.peek() {
            Some(b'[') => {
                let had_content = self.peek_nonblank_after_bracket();
                (self.blank_node_property_list()?, had_content)
            }
            Some(b'(') => (self.collection()?, false),
            _ => (self.subject_term()?, false),
        };
        self.ws();
        if was_property_list && self.peek() == Some(b'.') {
            self.i += 1;
            return Ok(());
        }
        self.predicate_object_list(&subject)?;
        self.expect(b'.')
    }

    fn peek_nonblank_after_bracket(&self) -> bool {
        let mut j = self.i + 1;
        while let Some(&c) = self.s.get(j) {
            if c.is_ascii_whitespace() {
                j += 1;
            } else {
                return c != b']';
            }
        }
        false
    }

    fn subject_term(&mut self) -> Result<Term> {
        match self.peek() {
            Some(b'<') => Ok(Term::Iri(self.iri_ref()?)),
            Some(b'_') if self.peek_at(1) == Some(b':') => self.blank_label(),
            Some(_) => Ok(Term::Iri(self.prefixed_name()?)),
            None => self.err("unexpected end of input"),
        }
    }

    fn predicate_object_list(&mut self, subject: &Term) -> Result<()> {
        loop {
            self.ws();
            let verb = self.verb()?;
            self.object_list(subject, &verb)?;
            self.ws();
            if self.peek() == Some(b';') {
                while self.peek() == Some(b';') {
                    self.i += 1;
                    self.ws();
                }
                match self.peek() {
                    Some(b'.') | Some(b']') | None => return Ok(()),
                    _ => continue,
                }
            }
            return Ok(());
        }
    }

    fn verb(&mut self) -> Result<String> {
        if self.peek() == Some(b'a')
            && !matches!(self.peek_at(1), Some(c) if is_name_byte(c) || c == b':' || c == b'.')
        {
            self.i += 1;
            return Ok(RDF_TYPE.to_string());
        }
        match self.peek() {
            Some(b'<') => self.iri_ref(),
            Some(_) => self.prefixed_name(),
            None => self.err("expected a predicate"),
        }
    }

    fn object_list(&mut self, subject: &Term, verb: &str) -> Result<()> {
        loop {
            self.ws();
            let o = self.object()?;
            self.push(subject.clone(), verb.to_string(), o)?;
            self.ws();
            if self.peek() == Some(b',') {
                self.i += 1;
                continue;
            }
            return Ok(());
        }
    }

    fn object(&mut self) -> Result<Term> {
        match self.peek() {
            Some(b'<') => Ok(Term::Iri(self.iri_ref()?)),
            Some(b'_') if self.peek_at(1) == Some(b':') => self.blank_label(),
            Some(b'[') => self.blank_node_property_list(),
            Some(b'(') => self.collection(),
            Some(b'"') | Some(b'\'') => self.rdf_literal(),
            Some(c) if c.is_ascii_digit() || c == b'+' || c == b'-' || c == b'.' => self.numeric(),
            Some(_)
                if self.starts_with_keyword_ci("true") || self.starts_with_keyword_ci("false") =>
            {
                let v = if self.starts_with(b"true") || self.starts_with(b"TRUE") {
                    "true"
                } else {
                    "false"
                };
                self.i += v.len();
                Ok(Term::Literal(Literal {
                    value: v.into(),
                    datatype: Some(format!("{}boolean", XSD)),
                    lang: None,
                }))
            }
            Some(_) => Ok(Term::Iri(self.prefixed_name()?)),
            None => self.err("expected an object"),
        }
    }

    fn enter(&mut self) -> Result<()> {
        self.depth += 1;
        if self.depth > MAX_DEPTH {
            return Err(Aff4Error::Limit(format!(
                "nesting deeper than {} at byte {}",
                MAX_DEPTH, self.i
            )));
        }
        Ok(())
    }

    fn blank_node_property_list(&mut self) -> Result<Term> {
        self.enter()?;
        self.i += 1; // '['
        let node = self.new_bnode();
        self.ws();
        if self.peek() != Some(b']') {
            self.predicate_object_list(&node)?;
        }
        self.expect(b']')?;
        self.depth -= 1;
        Ok(node)
    }

    fn collection(&mut self) -> Result<Term> {
        self.enter()?;
        self.i += 1; // '('
        let mut items = Vec::new();
        loop {
            self.ws();
            match self.peek() {
                Some(b')') => {
                    self.i += 1;
                    break;
                }
                None => return self.err("unterminated collection"),
                _ => items.push(self.object()?),
            }
        }
        self.depth -= 1;
        let nil = Term::Iri(format!("{}nil", RDF));
        if items.is_empty() {
            return Ok(nil);
        }
        let nodes: Vec<Term> = items.iter().map(|_| self.new_bnode()).collect();
        for (k, item) in items.into_iter().enumerate() {
            self.push(nodes[k].clone(), format!("{}first", RDF), item)?;
            let rest = nodes.get(k + 1).cloned().unwrap_or_else(|| nil.clone());
            self.push(nodes[k].clone(), format!("{}rest", RDF), rest)?;
        }
        Ok(nodes[0].clone())
    }

    fn blank_label(&mut self) -> Result<Term> {
        self.i += 2; // "_:"
        let start = self.i;
        while let Some(c) = self.peek() {
            if is_name_byte(c) || c == b'.' {
                self.i += 1;
            } else {
                break;
            }
        }
        while self.i > start && self.s[self.i - 1] == b'.' {
            self.i -= 1;
        }
        if self.i == start {
            return self.err("empty blank node label");
        }
        Ok(Term::Blank(
            String::from_utf8_lossy(&self.s[start..self.i]).into_owned(),
        ))
    }

    fn resolve(&self, iri: String) -> String {
        let has_scheme = iri
            .find(':')
            .map(|k| {
                k > 0
                    && iri.as_bytes()[0].is_ascii_alphabetic()
                    && iri[..k]
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b == b'+' || b == b'-' || b == b'.')
            })
            .unwrap_or(false);
        if has_scheme || self.base.is_empty() {
            iri
        } else {
            format!("{}{}", self.base, iri)
        }
    }

    fn iri_ref(&mut self) -> Result<String> {
        if self.peek() != Some(b'<') {
            return self.err("expected '<'");
        }
        self.i += 1;
        let mut out: Vec<u8> = Vec::new();
        loop {
            match self.peek() {
                None => return self.err("unterminated IRI"),
                Some(b'>') => {
                    self.i += 1;
                    break;
                }
                Some(b'\\') => {
                    self.i += 1;
                    let c = self.unicode_escape()?;
                    let mut b = [0u8; 4];
                    out.extend_from_slice(c.encode_utf8(&mut b).as_bytes());
                }
                Some(b'\n') | Some(b'\r') => return self.err("newline in IRI"),
                Some(c) => {
                    out.push(c);
                    self.i += 1;
                }
            }
        }
        Ok(self.resolve(String::from_utf8_lossy(&out).into_owned()))
    }

    fn unicode_escape(&mut self) -> Result<char> {
        let n = match self.peek() {
            Some(b'u') => 4,
            Some(b'U') => 8,
            _ => return self.err("bad escape"),
        };
        self.i += 1;
        let hex = self
            .s
            .get(self.i..self.i + n)
            .ok_or_else(|| Aff4Error::Turtle(format!("truncated escape at byte {}", self.i)))?;
        let v = u32::from_str_radix(&String::from_utf8_lossy(hex), 16)
            .map_err(|_| Aff4Error::Turtle(format!("bad escape at byte {}", self.i)))?;
        self.i += n;
        Ok(char::from_u32(v).unwrap_or('\u{fffd}'))
    }

    fn prefixed_name(&mut self) -> Result<String> {
        let start = self.i;
        while let Some(c) = self.peek() {
            if is_name_byte(c) || c == b'.' {
                self.i += 1;
            } else {
                break;
            }
        }
        if self.peek() != Some(b':') {
            self.i = start;
            return self.err("expected a prefixed name, IRI or literal");
        }
        let prefix = String::from_utf8_lossy(&self.s[start..self.i]).into_owned();
        self.i += 1;
        let mut local: Vec<u8> = Vec::new();
        while let Some(c) = self.peek() {
            if is_name_byte(c) || c == b'.' || c == b':' || c == b'%' {
                local.push(c);
                self.i += 1;
            } else if c == b'\\' {
                match self.peek_at(1) {
                    Some(e) if !e.is_ascii_whitespace() => {
                        local.push(e);
                        self.i += 2;
                    }
                    _ => break,
                }
            } else {
                break;
            }
        }
        while local.last() == Some(&b'.') {
            local.pop();
            self.i -= 1;
        }
        let ns = match self.prefixes.get(&prefix) {
            Some(ns) => ns.clone(),
            None => return self.err(&format!("undeclared prefix '{}:'", prefix)),
        };
        Ok(format!("{}{}", ns, String::from_utf8_lossy(&local)))
    }

    fn string(&mut self) -> Result<String> {
        let q = self.peek().unwrap_or(b'"');
        let long = self.s.get(self.i..self.i + 3) == Some(&[q, q, q][..]);
        self.i += if long { 3 } else { 1 };
        let mut out: Vec<u8> = Vec::new();
        loop {
            let c = match self.peek() {
                Some(c) => c,
                None => return self.err("unterminated string"),
            };
            if c == q {
                if !long {
                    self.i += 1;
                    break;
                }
                if self.s.get(self.i..self.i + 3) == Some(&[q, q, q][..]) {
                    // A long string may end with up to two extra quotes before the closing three.
                    let mut end = self.i + 3;
                    while self.s.get(end) == Some(&q) && end - self.i < 5 {
                        end += 1;
                    }
                    for _ in 0..end - self.i - 3 {
                        out.push(q);
                    }
                    self.i = end;
                    break;
                }
                out.push(c);
                self.i += 1;
                continue;
            }
            if !long && (c == b'\n' || c == b'\r') {
                return self.err("newline in short string");
            }
            if c == b'\\' {
                self.i += 1;
                let e = match self.peek() {
                    Some(e) => e,
                    None => return self.err("unterminated escape"),
                };
                let ch = match e {
                    b't' => '\t',
                    b'b' => '\u{8}',
                    b'n' => '\n',
                    b'r' => '\r',
                    b'f' => '\u{c}',
                    b'"' => '"',
                    b'\'' => '\'',
                    b'\\' => '\\',
                    b'u' | b'U' => {
                        let ch = self.unicode_escape()?;
                        let mut b = [0u8; 4];
                        out.extend_from_slice(ch.encode_utf8(&mut b).as_bytes());
                        continue;
                    }
                    _ => return self.err("bad string escape"),
                };
                self.i += 1;
                let mut b = [0u8; 4];
                out.extend_from_slice(ch.encode_utf8(&mut b).as_bytes());
                continue;
            }
            out.push(c);
            self.i += 1;
        }
        Ok(String::from_utf8_lossy(&out).into_owned())
    }

    fn rdf_literal(&mut self) -> Result<Term> {
        let value = self.string()?;
        let mut lit = Literal {
            value,
            datatype: None,
            lang: None,
        };
        if self.peek() == Some(b'@') {
            self.i += 1;
            let start = self.i;
            while let Some(c) = self.peek() {
                if c.is_ascii_alphanumeric() || c == b'-' {
                    self.i += 1;
                } else {
                    break;
                }
            }
            if self.i == start {
                return self.err("empty language tag");
            }
            lit.lang = Some(String::from_utf8_lossy(&self.s[start..self.i]).to_ascii_lowercase());
        } else if self.starts_with(b"^^") {
            self.i += 2;
            let dt = match self.peek() {
                Some(b'<') => self.iri_ref()?,
                _ => self.prefixed_name()?,
            };
            lit.datatype = Some(dt);
        }
        Ok(Term::Literal(lit))
    }

    fn numeric(&mut self) -> Result<Term> {
        let start = self.i;
        if matches!(self.peek(), Some(b'+') | Some(b'-')) {
            self.i += 1;
        }
        let mut digits = 0;
        while matches!(self.peek(), Some(c) if c.is_ascii_digit()) {
            self.i += 1;
            digits += 1;
        }
        let mut kind = "integer";
        if self.peek() == Some(b'.') && matches!(self.peek_at(1), Some(c) if c.is_ascii_digit()) {
            self.i += 1;
            kind = "decimal";
            while matches!(self.peek(), Some(c) if c.is_ascii_digit()) {
                self.i += 1;
                digits += 1;
            }
        }
        if matches!(self.peek(), Some(b'e') | Some(b'E')) {
            let save = self.i;
            self.i += 1;
            if matches!(self.peek(), Some(b'+') | Some(b'-')) {
                self.i += 1;
            }
            let mut exp = 0;
            while matches!(self.peek(), Some(c) if c.is_ascii_digit()) {
                self.i += 1;
                exp += 1;
            }
            if exp == 0 {
                self.i = save;
            } else {
                kind = "double";
            }
        }
        if digits == 0 {
            self.i = start;
            return self.err("bad number");
        }
        Ok(Term::Literal(Literal {
            value: String::from_utf8_lossy(&self.s[start..self.i]).into_owned(),
            datatype: Some(format!("{}{}", XSD, kind)),
            lang: None,
        }))
    }
}

/// Escape a string for a Turtle short string literal.
pub fn escape_literal(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04X}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::AFF4;

    #[test]
    fn pyaff4_style() {
        let doc = r#"@prefix aff4: <http://aff4.org/Schema#> .
@prefix xsd: <http://www.w3.org/2001/XMLSchema#> .

<aff4://img> a aff4:DiskImage,
        aff4:Image ;
    aff4:dataStream <aff4://map> ;
    aff4:hash "c7f4"^^aff4:MD5,
        "e4e3"^^aff4:SHA1 .

<aff4://s> a aff4:ImageStream ;
    aff4:chunkSize 32768 ;
    aff4:size "170000"^^xsd:long ;
    aff4:compressionMethod <http://code.google.com/p/snappy/> .
"#;
        let g = parse(doc).unwrap();
        assert!(g.has_type("aff4://img", &format!("{}Image", AFF4)));
        assert_eq!(
            g.subjects_of_type(&format!("{}ImageStream", AFF4)),
            vec!["aff4://s".to_string()]
        );
        let h = g.objects("aff4://img", "http://aff4.org/Schema#hash");
        assert_eq!(h.len(), 2);
        assert_eq!(
            h[1].as_literal().unwrap().datatype.as_deref(),
            Some("http://aff4.org/Schema#SHA1")
        );
        assert_eq!(
            g.object("aff4://s", "http://aff4.org/Schema#size")
                .unwrap()
                .as_u64(),
            Some(170000)
        );
    }

    #[test]
    fn syntax_variety() {
        let doc = "PREFIX ex: <http://e/>\n BASE <http://b/>\n<rel> ex:p 'a\\'b', \"\"\"x\n\"y\"\"\"\" , -1.5e3, true, ( 1 2 ), [ ex:q _:n1 ] ; ex:r \"t\"@en-GB ;; . # c\n[ ex:p 1 ] .\n";
        let g = parse(doc).unwrap();
        let o = g.objects("http://b/rel", "http://e/p");
        assert_eq!(o.len(), 6);
        assert_eq!(o[0].lexical(), "a'b");
        assert_eq!(o[1].lexical(), "x\n\"y\"");
        assert_eq!(o[2].lexical(), "-1.5e3");
        assert_eq!(o[3].lexical(), "true");
    }

    #[test]
    fn errors_not_panics() {
        for bad in [
            "<a> <b> .",
            "<a> <b> \"x",
            "@prefix x <y> .",
            "<a> y:z <c> .",
            "<a> <b> <c>",
            "<a",
            "[[[[",
            "<a> <b> ((((",
            "_: <b> <c> .",
            "<a> <b> \"\\u12\" .",
        ] {
            assert!(parse(bad).is_err(), "{}", bad);
        }
        let deep = "<a> <b> ".to_string() + &"[ <p> ".repeat(100) + &"]".repeat(100) + " .";
        assert!(matches!(parse(&deep), Err(Aff4Error::Limit(_))));
    }
}
