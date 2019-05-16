#[cfg(feature = "encryption")]
use rustls::{ClientConfig, ClientSession, Session};
use std::cmp::min;
use std::io::BufRead;
use std::io::{BufReader, Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::num::NonZeroU32;
use std::sync::Arc;
#[cfg(feature = "encryption")]
use webpki::DNSNameRef;

pub struct Pop3Client {
    client: BufReader<TcpStream>,
    #[cfg(feature = "encryption")]
    tls: ClientSession,
    authorized: bool,
}

type Pop3Result = Result<String, String>;

impl Pop3Client {
    #[cfg(not(feature = "encryption"))]
    pub fn connect(addr: impl Into<SocketAddr>) -> Option<Self> {
        TcpStream::connect(addr.into())
            .map(|client| Self {
                client: BufReader::new(client),
                authorized: false,
            })
            .map(|mut client| {
                client
                    .read_response(false)
                    .map_err(|e| eprintln!("{:?}", e))
                    .ok()
                    .map(|_| client)
            })
            .map_err(|e| eprintln!("{:?}", e))
            .unwrap_or(None)
    }

    #[cfg(feature = "encryption")]
    pub fn connect(
        addr: impl Into<SocketAddr>,
        config: Arc<ClientConfig>,
        hostname: DNSNameRef,
    ) -> Option<Self> {
        TcpStream::connect(addr.into())
            .map(|client| Self {
                client: BufReader::new(client),
                tls: ClientSession::new(&config, hostname),
                authorized: false,
            })
            .map(|mut client| {
                let mut buf = String::new();
                client
                    .client
                    .read_line(&mut buf)
                    .map_err(|e| e.to_string())
                    .and_then(|_| {
                        if buf.starts_with("+OK") {
                            Ok(buf[4..].to_owned())
                        } else {
                            Err(buf[5..].to_owned())
                        }
                    })
                    .map_err(|e| eprintln!("Connect: {:?}", e))
                    .ok()
                    .map(|_| client)
            })
            .map(|client| {
                client.map(|mut client| {
                    client
                        .client
                        .get_mut()
                        .write_all("STLS\r\n".as_bytes())
                        .map_err(|e| e.to_string())
                        .and_then(|_| {
                            let mut buf = String::new();
                            client
                                .client
                                .read_line(&mut buf)
                                .map_err(|e| e.to_string())
                                .and_then(|_| {
                                    if buf.starts_with("+OK") {
                                        Ok(buf[4..].to_owned())
                                    } else {
                                        Err(buf[5..].to_owned())
                                    }
                                })
                        })
                        .map_err(|e| eprintln!("Starttls: {:?}", e))
                        .ok()
                        .map(|_| client)
                })
            })
            .map_err(|e| eprintln!("{:?}", e))
            .unwrap_or(None)
            .unwrap_or(None)
    }

    pub fn login(&mut self, login: impl Into<String>, password: impl Into<String>) -> Pop3Result {
        if self.authorized {
            return Err("login is only allowed in Authorization stage".to_string());
        }
        let login_query = format!("USER {}\r\n", login.into());
        let password_query = format!("PASS {}\r\n", password.into());

        self.send(login_query, false).and_then(|s1| {
            self.send(password_query, false)
                .map(|s2| format!("{}{}", s1, s2))
                .map(|s| {
                    self.authorized = true;
                    s
                })
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
        if self.authorized {
            return Err("login is only allowed in Authorization stage".to_string());
        }
        let query = format!("APOP {} {}\r\n", name, digest);
        self.send(query, false).map(|s| {
            self.authorized = true;
            s
        })
    }

    #[cfg(not(feature = "encryption"))]
    fn read_response(&mut self, multiline: bool) -> Pop3Result {
        let mut response = String::new();
        let mut buffer = String::new();
        self.client
            .read_line(&mut buffer)
            .map_err(|e| e.to_string())
            .and_then(|x| {
                if x == 0 {
                    Err("Connection aborted".to_string())
                } else {
                    Ok(x)
                }
            })
            .and_then(|_| {
                if buffer.starts_with("+OK") {
                    Ok(buffer[4..].to_owned())
                } else {
                    Err(if buffer.len() < 6 {
                        buffer.clone()
                    } else {
                        buffer[5..].to_owned()
                    })
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
                        eprintln!("Buffer content: {}", buffer);
                        response.push_str(&buffer);
                    }
                    Ok(response)
                } else {
                    Ok(s)
                }
            })
    }

    #[cfg(feature = "encryption")]
    fn read_response(&mut self) -> Pop3Result {
        let mut response = String::new();
        let mut buffer = Vec::new();
        while self.tls.wants_read() {
            let res = self
                .tls
                .read_tls(&mut self.client)
                .map_err(|e| e.to_string())
                .and_then(|_| self.tls.process_new_packets().map_err(|e| e.to_string()))
                .and_then(|_| {
                    self.tls
                        .read_to_end(&mut buffer)
                        .map_err(|e| e.to_string())
                        .and_then(|x| {
                            if x == 0 {
                                Err("Connection aborted".to_string())
                            } else {
                                Ok(x)
                            }
                        })
                        .and_then(|_| String::from_utf8(buffer.clone()).map_err(|e| e.to_string()))
                })
                .map(|s| response.push_str(&s))
                .map(|_| buffer.clear())
                .map(|_| String::new());
            if res.is_err() {
                eprintln!("Err reading TLS: {}", response);
                return res;
            }
        }

        if response.starts_with("+OK") {
            Ok(response[4..].to_owned())
        } else {
            Err(response[5..].to_owned())
        }
    }

    #[cfg(not(feature = "encryption"))]
    fn send(&mut self, query: String, multiline: bool) -> Pop3Result {
        self.client
            .get_mut()
            .write_all(query.as_bytes())
            .map_err(|e| e.to_string())
            .and_then(|_| self.read_response(multiline))
            .map_err(|e| {
                eprintln!("Error: {}", e);
                e
            })
    }

    #[cfg(feature = "encryption")]
    fn send(&mut self, query: String, _multiline: bool) -> Pop3Result {
        self.tls
            .write_all(query.as_bytes())
            .map_err(|e| e.to_string())
            .and_then(|_| {
                let mut res = Ok(0);
                while self.tls.wants_write() {
                    let write = self
                        .tls
                        .write_tls(&mut self.client.get_mut())
                        .map_err(|e| e.to_string());
                    res = res.and(write);
                }
                res
            })
            .and_then(|_| self.read_response())
    }
}

#[cfg(test)]
mod tests {
    use crate::Pop3Client;
    #[cfg(feature = "encryption")]
    use rustls::ClientConfig;
    use std::net::ToSocketAddrs;
    use std::sync::Arc;
    #[cfg(feature = "encryption")]
    use webpki::DNSNameRef;
    #[cfg(feature = "encryption")]
    use webpki_roots;

    #[cfg(not(feature = "encryption"))]
    fn connect() -> Option<Pop3Client> {
        Pop3Client::connect(
            "pop3.mailtrap.io:1100"
                .to_socket_addrs()
                .expect("Failed to make SocketAddr")
                .collect::<Vec<_>>()[0],
        )
    }

    #[cfg(feature = "encryption")]
    fn connect() -> Option<Pop3Client> {
        let mut config = ClientConfig::new();
        config
            .root_store
            .add_server_trust_anchors(&webpki_roots::TLS_SERVER_ROOTS);
        let config = Arc::new(config);
        Pop3Client::connect(
            "pop3.mailtrap.io:9950"
                .to_socket_addrs()
                .expect("Failed to make SocketAddr")
                .collect::<Vec<_>>()[0],
            config,
            DNSNameRef::try_from_ascii_str("pop3.mailtrap.io").expect("Failed to make DNSNameRef"),
        )
    }

    #[test]
    fn connects() {
        assert!(connect().is_some());
    }

    #[test]
    fn login_success() {
        let mut client = connect().unwrap();
        let result = client.login("e913202b66b623", "1ddf1a9bd7fc45");
        eprintln!("login_success: {:?}", result);
        assert!(result.is_ok())
    }

    #[test]
    fn login_wrong_login() {
        let mut client = connect().unwrap();
        let result = client.login("e913202b66b62", "1ddf1a9bd7fc45");
        eprintln!("wrong_login: {:?}", result);
        assert!(result.is_err())
    }

    #[test]
    fn login_wrong_password() {
        let mut client = connect().unwrap();
        let result = client.login("e913202b66b623", "1ddf1a9bd7fc4");
        eprintln!("wrong_password: {:?}", result);
        assert!(result.is_err())
    }

    #[test]
    fn login_wrong_stage() {
        let mut client = connect().unwrap();
        client.login("e913202b66b623", "1ddf1a9bd7fc45").ok();
        let result = client.login("e913202b66b623", "1ddf1a9bd7fc45");
        eprintln!("login_wrong_stage: {:?}", result);
        assert!(result.is_err())
    }

    // This test will fail if the server implementation does not comply to specification
    #[cfg(false)]
    #[test]
    fn login_already_locked() {
        connect()
            .unwrap()
            .login("e913202b66b623", "1ddf1a9bd7fc45")
            .ok();
        let mut client = connect().unwrap();
        let result = client.login("e913202b66b623", "1ddf1a9bd7fc45");
        eprintln!("login_already_locked: {:?}", result);
        assert!(result.is_err())
    }

    // TODO
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
