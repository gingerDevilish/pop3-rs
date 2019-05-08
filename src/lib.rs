use rustls::{ClientConfig, ClientSession};
use std::io::{BufRead, BufReader, Write};
use std::net::{SocketAddr, TcpStream};
use std::num::NonZeroU32;
use std::sync::Arc;
use webpki::DNSNameRef;

pub struct Pop3Client {
    #[cfg(not(feature = "encryption"))]
    client: BufReader<TcpStream>,
    #[cfg(feature = "encryption")]
    client: TcpStream,
    #[cfg(feature = "encryption")]
    tls: BufReader<ClientSession>,
}

type Pop3Result = Result<String, String>;

impl Pop3Client {
    #[cfg(not(feature = "encryption"))]
    pub fn connect(addr: impl Into<SocketAddr>) -> Option<Self> {
        TcpStream::connect(addr.into())
            .map(|client| Self {
                client: BufReader::new(client),
            })
            .map(|mut client| {
                if client.read_response(false).is_ok() {
                    Some(client)
                } else {
                    None
                }
            })
            .unwrap_or(None)
    }

    #[cfg(feature = "encryption")]
    pub fn connect(
        addr: impl Into<SocketAddr>,
        config: Arc<ClientConfig>,
        hostname: DNSNameRef,
    ) -> Option<Self> {
        unimplemented!()
    }

    pub fn login(&mut self, login: impl Into<String>, password: impl Into<String>) -> Pop3Result {
        let login_query = format!("USER {}\r\n", login.into());
        let password_query = format!("PASS {}\r\n", password.into());

        self.send(login_query, false).and_then(|s1| {
            self.send(password_query, false)
                .map(|s2| format!("{}{}", s1, s2))
        })
    }

    pub fn quit(mut self) -> Pop3Result {
        let query = "QUIT\r\n".to_string();
        self.send(query, false)
    }

    pub fn stat(&mut self) -> Pop3Result {
        let query = "STAT\r\n".to_string();
        self.send(query, false)
    }

    pub fn list(&mut self, msg: Option<NonZeroU32>) -> Pop3Result {
        let query = if let Some(num) = msg {
            format!("LIST {}\r\n", num)
        } else {
            "LIST\r\n".to_string()
        };
        self.send(query, msg.is_none())
    }

    pub fn retr(&mut self, msg: NonZeroU32) -> Pop3Result {
        let query = format!("RETR {}\r\n", msg);
        self.send(query, true)
    }

    pub fn dele(&mut self, msg: NonZeroU32) -> Pop3Result {
        let query = format!("DELE {}\r\n", msg);
        self.send(query, false)
    }

    pub fn noop(&mut self) -> Pop3Result {
        let query = "NOOP\r\n".to_string();
        self.send(query, false)
    }

    pub fn rset(&mut self) -> Pop3Result {
        let query = "RSET\r\n".to_string();
        self.send(query, false)
    }

    pub fn top(&mut self, msg: NonZeroU32, n: u32) -> Pop3Result {
        let query = format!("TOP {} {}\r\n", msg, n);
        self.send(query, true)
    }

    pub fn uidl(&mut self, msg: Option<NonZeroU32>) -> Pop3Result {
        let query = if let Some(num) = msg {
            format!("UIDL {}\r\n", num)
        } else {
            "UIDL\r\n".to_string()
        };
        self.send(query, msg.is_none())
    }

    pub fn apop(&mut self, name: String, digest: String) -> Pop3Result {
        let query = format!("APOP {} {}\r\n", name, digest);
        self.send(query, false)
    }

    #[cfg(not(feature = "encryption"))]
    fn read_response(&mut self, multiline: bool) -> Pop3Result {
        let mut response = String::new();
        let mut buffer = String::new();
        self.client
            .read_line(&mut buffer)
            .map_err(|e| e.to_string())
            .and_then(|_| {
                if buffer.starts_with("+OK") {
                    Ok(buffer[4..].to_owned())
                } else {
                    Err(buffer[5..].to_owned())
                }
            })
            .and_then(|s| {
                if multiline {
                    response.push_str(&s);
                    while !buffer.ends_with(".\r\n") {
                        buffer.clear();
                        let read = self
                            .client
                            .read_line(&mut buffer)
                            .map_err(|e| e.to_string())
                            .and_then(|x| {
                                if x == 0 {
                                    Err("Connection aborted".to_string())
                                } else {
                                    Ok(x)
                                }
                            })
                            .map(|_| String::new());
                        if read.is_err() {
                            return read;
                        }
                        response.push_str(&buffer);
                    }
                    Ok(response)
                } else {
                    Ok(s)
                }
            })
    }

    #[cfg(not(feature = "encryption"))]
    fn send(&mut self, query: String, multiline: bool) -> Pop3Result {
        self.client
            .get_mut()
            .write_all(query.as_bytes())
            .map_err(|e| e.to_string())
            .and_then(|_| self.read_response(multiline))
    }

    #[cfg(feature = "encryption")]
    fn send(&mut self, query: String, multiline: bool) -> Pop3Result {
        unimplemented!()
    }
}

// TODO logging?
// impl for TLS version

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }

    // TODO
    // test connect
    // test login (succ, wrong login, wrong pass, wrong stage, already locked)
    // test apop (succ, wrong login, wrong digest, wrong stage, already locked)
    // test quit
    // test stat (succ, wrong stage)
    // test list (all list,single ok, single err; wrong stage)
    // test retr (succ, not found, wrong stage)
    // test dele (succ, not found, wrong stage)
    // test noop (succ, wrong stage)
    // test rset (succ, wrong stage)
    // test top (succ, not found, wrong stage)
    // test uidl (all list, single ok, single err, wrong stage)
}
