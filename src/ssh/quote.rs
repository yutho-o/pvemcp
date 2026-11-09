//! Shell quoting. Every value that goes into a command goes through here.

use crate::errors::{PveError, Result};

/// Quotes a value for a POSIX shell: inside single quotes nothing is special but the quote
/// itself. NUL cannot be in an argument at all, and silently truncating at one would run
/// something other than what was asked.
pub fn sh_quote(value: impl std::fmt::Display) -> Result<String> {
    let text = value.to_string();
    if text.contains('\0') {
        return Err(PveError::invalid("A shell argument holds a NUL character."));
    }
    Ok(format!("'{}'", text.replace('\'', r"'\''")))
}

/// What the sh! macro can insert: quoted values, lists of quoted words, or raw text written in the code.
pub enum ShellArg {
    Quoted(String),
    List(Vec<String>),
    /// Inserted as it is. For operators and fragments written in the code, never for input.
    Raw(String),
}

impl ShellArg {
    pub fn render(&self) -> Result<String> {
        match self {
            ShellArg::Quoted(s) => sh_quote(s),
            ShellArg::List(items) => Ok(items.iter().map(sh_quote).collect::<Result<Vec<_>>>()?.join(" ")),
            ShellArg::Raw(s) => Ok(s.clone()),
        }
    }
}

impl From<&str> for ShellArg {
    fn from(s: &str) -> Self {
        ShellArg::Quoted(s.to_string())
    }
}
impl From<String> for ShellArg {
    fn from(s: String) -> Self {
        ShellArg::Quoted(s)
    }
}
impl From<&String> for ShellArg {
    fn from(s: &String) -> Self {
        ShellArg::Quoted(s.clone())
    }
}
macro_rules! numeric_arg {
    ($($t:ty),*) => { $( impl From<$t> for ShellArg { fn from(n: $t) -> Self { ShellArg::Quoted(n.to_string()) } } )* };
}
numeric_arg!(i32, i64, u16, u32, u64, usize);
impl From<Vec<String>> for ShellArg {
    fn from(v: Vec<String>) -> Self {
        ShellArg::List(v)
    }
}
impl From<&[String]> for ShellArg {
    fn from(v: &[String]) -> Self {
        ShellArg::List(v.to_vec())
    }
}
impl From<&Vec<String>> for ShellArg {
    fn from(v: &Vec<String>) -> Self {
        ShellArg::List(v.clone())
    }
}

/// Raw text for sh!: shRaw() of the TypeScript version.
pub fn raw(text: impl Into<String>) -> ShellArg {
    ShellArg::Raw(text.into())
}

/// Shell text where every {} is quoted, as the sh`` tag did: a list becomes several quoted words,
/// raw(...) goes in as it is. Returns Result<String>.
///
/// ```ignore
/// let cmd = sh!("pct exec {} -- cat {}", vmid, path)?;
/// ```
#[macro_export]
macro_rules! sh {
    ($fmt:literal $(, $arg:expr)* $(,)?) => {{
        (|| -> $crate::errors::Result<String> {
            let args: Vec<$crate::ssh::quote::ShellArg> = vec![$($crate::ssh::quote::ShellArg::from($arg)),*];
            $crate::ssh::quote::render($fmt, &args)
        })()
    }};
}

/// Fills each {} in fmt with the next argument, rendered. {{ and }} are literal braces.
pub fn render(fmt: &str, args: &[ShellArg]) -> Result<String> {
    let mut out = String::with_capacity(fmt.len());
    let mut next = args.iter();
    let mut chars = fmt.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '{' if chars.peek() == Some(&'{') => {
                chars.next();
                out.push('{');
            }
            '}' if chars.peek() == Some(&'}') => {
                chars.next();
                out.push('}');
            }
            '{' if chars.peek() == Some(&'}') => {
                chars.next();
                let arg = next.next().expect("sh!: more {} than arguments");
                out.push_str(&arg.render()?);
            }
            other => out.push(other),
        }
    }
    assert!(next.next().is_none(), "sh!: more arguments than {{}}");
    Ok(out)
}

impl From<ShellArg> for String {
    fn from(a: ShellArg) -> String {
        a.render().unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quotes() {
        assert_eq!(sh_quote("it's").unwrap(), r"'it'\''s'");
        let cmd = crate::sh!("pct exec {} -- cat {} {}", 100, "/etc/x y", raw("| head")).unwrap();
        assert_eq!(cmd, "pct exec '100' -- cat '/etc/x y' | head");
        let list = crate::sh!("apt-get install {}", vec!["a".to_string(), "b".to_string()]).unwrap();
        assert_eq!(list, "apt-get install 'a' 'b'");
        assert!(sh_quote("a\0b").is_err());
    }

    #[test]
    fn leaves_nothing_special_inside_the_quotes() {
        assert_eq!(sh_quote("plain").unwrap(), "'plain'");
        assert_eq!(sh_quote("a b").unwrap(), "'a b'");
        assert_eq!(sh_quote("$(reboot); `id` | x > y").unwrap(), "'$(reboot); `id` | x > y'");
        assert_eq!(sh_quote("-rf").unwrap(), "'-rf'");
        assert_eq!(sh_quote("").unwrap(), "''");
        assert_eq!(sh_quote(100).unwrap(), "'100'");
    }

    #[test]
    fn the_sh_macro() {
        // Every interpolation is quoted.
        assert_eq!(crate::sh!("pct exec {} -- cat {}", 100, "/etc/os release; id").unwrap(), "pct exec '100' -- cat '/etc/os release; id'");
        // A list becomes several quoted words, an empty one none.
        assert_eq!(crate::sh!("apt-get install -y -- {}", vec!["curl".to_string(), "a b".to_string()]).unwrap(), "apt-get install -y -- 'curl' 'a b'");
        assert_eq!(crate::sh!("x {}", Vec::<String>::new()).unwrap(), "x ");
        // Only what is marked raw goes in as it is.
        assert_eq!(crate::sh!("{} ls {}", raw("cd /tmp &&"), "$HOME").unwrap(), "cd /tmp && ls '$HOME'");
        let inner = crate::sh!("echo {}", "a;b").unwrap();
        assert_eq!(crate::sh!("sudo -n {}", raw(inner)).unwrap(), "sudo -n echo 'a;b'");
        // An injection attempt stays one word.
        assert_eq!(crate::sh!("cat {}", "'; rm -rf / #").unwrap(), r"cat ''\''; rm -rf / #'");
        // NUL is refused through any route.
        assert!(crate::sh!("x {}", "a\0").is_err());
        assert!(crate::sh!("x {}", vec!["a\0".to_string()]).is_err());
    }
}
