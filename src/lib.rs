use failure::Error;
use lazy_static::lazy_static;
use regex::Regex;
use std::io::{BufReader, Write};
use std::net::{SocketAddr, TcpStream};
use std::num::NonZeroU32;

lazy_static! {
    static ref ENDING_REGEX: Regex = Regex::new(r"^\.\r\n$").unwrap();
    static ref OK_REGEX: Regex = Regex::new(r"\+OK(.*)").unwrap();
    static ref ERR_REGEX: Regex = Regex::new(r"-ERR(.*)").unwrap();
}

pub struct Pop3Client {
    client: BufReader<TcpStream>,
}

type Pop3Result = Result<String, String>;

impl Pop3Client {
    pub fn connect(addr: impl Into<SocketAddr>) -> Option<Self> {
        TcpStream::connect(addr.into())
            .map(|client| Self {
                client: BufReader::new(client),
            })
            .map(|mut client| {
                if client.read_response().is_ok() {
                    Some(client)
                } else {
                    None
                }
            })
            .unwrap_or(None)
    }

    pub fn login(&mut self, login: impl Into<String>, password: impl Into<String>) -> Pop3Result {
        let login_query = format!("USER {}\r\n", login.into());
        let password_query = format!("PASS {}\r\n", password.into());

        self.send(login_query)
            .and_then(|s1| self.send(password_query).map(|s2| format!("{}{}", s1, s2)))
    }

    pub fn quit(mut self) -> Pop3Result {
        let query = "QUIT\r\n".to_string();
        self.send(query)
    }

    pub fn stat(&mut self) -> Pop3Result {
        let query = "STAT\r\n".to_string();
        self.send(query)
    }

    pub fn list(&mut self, msg: Option<NonZeroU32>) -> Pop3Result {
        let query = if let Some(num) = msg {
            format!("LIST {}\r\n", num)
        } else {
            "LIST\r\n".to_string()
        };
        self.send(query)
    }

    pub fn retr(&mut self, msg: NonZeroU32) -> Pop3Result {
        let query = format!("RETR {}\r\n", msg);
        self.send(query)
    }

    pub fn dele(&mut self, msg: NonZeroU32) -> Pop3Result {
        let query = format!("DELE {}\r\n", msg);
        self.send(query)
    }

    pub fn noop(&mut self) -> Pop3Result {
        let query = "NOOP\r\n".to_string();
        self.send(query)
    }

    pub fn rset(&mut self) -> Pop3Result {
        let query = "RSET\r\n".to_string();
        self.send(query)
    }

    pub fn top(&mut self, msg: NonZeroU32, n: u32) -> Pop3Result {
        let query = format!("TOP {} {}\r\n", msg, n);
        self.send(query)
    }

    pub fn uidl(&mut self, msg: Option<NonZeroU32>) -> Pop3Result {
        let query = if let Some(num) = msg {
            format!("UIDL {}\r\n", num)
        } else {
            "UIDL\r\n".to_string()
        };
        self.send(query)
    }

    pub fn apop(&mut self, name: String, digest: String) -> Pop3Result {
        let query = format!("APOP {} {}\r\n", name, digest);
        self.send(query)
    }

    // transmute a response into a result
    fn read_response(&mut self) -> Pop3Result {
        unimplemented!()
    }

    fn send(&mut self, query: String) -> Pop3Result {
        self.client
            .get_mut()
            .write_all(query.as_bytes())
            .map_err(|e| e.to_string())
            .and_then(|_| self.read_response())
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
