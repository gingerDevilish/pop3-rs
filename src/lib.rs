use std::io::BufRead;
use std::io::{BufReader, Write};
use std::net::TcpStream;

#[cfg(feature = "with-rustls")]
use {
    rustls::StreamOwned,
    rustls::{ClientConfig, ClientSession},
    std::sync::Arc,
    webpki::DNSNameRef,
};

pub type Result<T> = std::result::Result<T, String>;

pub struct Builder {
    #[cfg(feature = "with-rustls")]
    config: Arc<ClientConfig>,
}

impl Default for Builder {
    #[cfg(not(feature = "with-rustls"))]
    fn default() -> Self {
        Self {}
    }

    #[cfg(feature = "with-rustls")]
    fn default() -> Self {
        let mut config = ClientConfig::new();
        config
            .root_store
            .add_server_trust_anchors(&webpki_roots::TLS_SERVER_ROOTS);

        let config = Arc::new(config);

        Self { config }
    }
}

impl Builder {
    #[cfg(not(feature = "with-rustls"))]
    pub fn connect(&mut self, host: &str, port: u16) -> Result<Client> {
        Client::connect_notls(host, port)
    }

    #[cfg(feature = "with-rustls")]
    pub fn connect(&mut self, host: &str, port: u16) -> Result<Client> {
        Client::connect_rustls(host, port, self.config.clone())
    }

    #[cfg(feature = "with-rustls")]
    pub fn rustls_config(&mut self, config: ClientConfig) -> &mut Self {
        self.config = Arc::new(config);
        self
    }
}

pub struct Client {
    #[cfg(feature = "with-rustls")]
    client: BufReader<StreamOwned<ClientSession, TcpStream>>,
    #[cfg(not(feature = "with-rustls"))]
    client: BufReader<TcpStream>,
    authorized: bool,
}

impl Client {
    pub fn connect(host: &str, port: u16) -> Result<Self> {
        Builder::default().connect(host, port)
    }

    pub fn login(&mut self, username: &str, password: &str) -> Result<()> {
        if self.authorized {
            return Err("login is only allowed in Authorization stage".to_string());
        }
        let username_query = format!("USER {}\r\n", username);
        let password_query = format!("PASS {}\r\n", password);

        self.send(&username_query, false)
            .and_then(|s1| {
                self.send(&password_query, false)
                    .map(|s2| format!("{}{}", s1, s2))
                    .map(|s| {
                        self.authorized = true;
                        s
                    })
            })
            .map(|_| ())
    }

    pub fn quit(mut self) -> Result<()> {
        self.send("QUIT\r\n", false).map(|_| ())
    }

    pub fn stat(&mut self) -> Result<(u32, u32)> {
        match self.send("STAT\r\n", false) {
            Err(e) => Err(e),
            Ok(ref s) => {
                let mut s = s
                    .trim()
                    .split(' ')
                    .map(|i| i.parse::<u32>().map_err(|e| e.to_string()));
                Ok((
                    s.next().ok_or_else(|| "INVALID_REPLY")??,
                    s.next().ok_or_else(|| "INVALID_REPLY")??,
                ))
            }
        }
    }

    pub fn list(&mut self, msg: Option<u32>) -> Result<String> {
        let query = if let Some(num) = msg {
            format!("LIST {}\r\n", num)
        } else {
            "LIST\r\n".to_string()
        };
        self.send(&query, msg.is_none())
    }

    pub fn retr(&mut self, msg: u32) -> Result<String> {
        let query = format!("RETR {}\r\n", msg);
        self.send(&query, true)
            .map(|s| s.split('\n').skip(1).collect::<Vec<&str>>().join("\n"))
    }

    pub fn dele(&mut self, msg: u32) -> Result<String> {
        let query = format!("DELE {}\r\n", msg);
        self.send(&query, false)
    }

    pub fn noop(&mut self) -> Result<()> {
        self.send("NOOP\r\n", false).map(|_| ())
    }

    pub fn rset(&mut self) -> Result<String> {
        self.send("RSET\r\n", false)
    }

    pub fn top(&mut self, msg: u32, n: u32) -> Result<String> {
        let query = format!("TOP {} {}\r\n", msg, n);
        self.send(&query, true)
    }

    pub fn uidl(&mut self, msg: Option<u32>) -> Result<String> {
        let query = if let Some(num) = msg {
            format!("UIDL {}\r\n", num)
        } else {
            "UIDL\r\n".to_string()
        };
        self.send(&query, msg.is_none())
    }

    pub fn apop(&mut self, name: String, digest: String) -> Result<String> {
        if self.authorized {
            return Err("login is only allowed in Authorization stage".to_string());
        }
        let query = format!("APOP {} {}\r\n", name, digest);
        self.send(&query, false).map(|s| {
            self.authorized = true;
            s
        })
    }

    #[cfg(not(feature = "with-rustls"))]
    fn connect_notls(host: &str, port: u16) -> Result<Self> {
        TcpStream::connect((host, port))
            .map(|client| Self {
                client: BufReader::new(client),
                authorized: false,
            })
            .map_err(|e| format!("{:?}", e))
            .and_then(|mut client| client.read_response(false).map(|_| client))
    }

    #[cfg(feature = "with-rustls")]
    fn connect_rustls(host: &str, port: u16, config: Arc<ClientConfig>) -> Result<Self> {
        let hostname = DNSNameRef::try_from_ascii_str(host).map_err(|_| "DNS_NAMEREF_FAILED")?;

        let session = ClientSession::new(&config, hostname);
        let socket = TcpStream::connect((host, port))
            .map(BufReader::new)
            .map_err(|e| format!("{:?}", e))
            .and_then(|mut client| {
                let mut buf = String::new();
                client
                    .read_line(&mut buf)
                    .map_err(|e| e.to_string())
                    .and_then(|_| {
                        if buf.starts_with("+OK") {
                            Ok(buf[4..].to_owned())
                        } else {
                            Err(buf[5..].to_owned())
                        }
                    })
                    .map(|_| client)
            })
            .and_then(|mut client| {
                client
                    .get_mut()
                    .write_all("STLS\r\n".as_bytes())
                    .map_err(|e| e.to_string())
                    .and_then(|_| {
                        let mut buf = String::new();
                        client
                            .read_line(&mut buf)
                            .map_err(|e| e.to_string())
                            .and_then(|_| {
                                println!("STLS: {}", &buf);
                                if buf.starts_with("+OK") {
                                    Ok(buf[4..].to_owned())
                                } else {
                                    Err(buf[5..].to_owned())
                                }
                            })
                    })
                    .map(|_| client.into_inner())
            })?;

        let tls_stream = StreamOwned::new(session, socket);

        Ok(Self {
            client: BufReader::new(tls_stream),
            authorized: false,
        })
    }

    fn read_response(&mut self, multiline: bool) -> Result<String> {
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
                        response.push_str(
                            &buffer[..buffer.len() - if buffer.ends_with(".\r\n") { 3 } else { 0 }],
                        );
                    }
                    Ok(response)
                } else {
                    Ok(s)
                }
            })
    }

    fn send(&mut self, query: &str, multiline: bool) -> Result<String> {
        self.client
            .get_mut()
            .write_all(query.as_bytes())
            .map_err(|e| e.to_string())
            .and_then(|_| self.read_response(multiline))
    }
}
