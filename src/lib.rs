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


/// A builder to create a [`Client`] with a connection.
///
/// As it is possible to create the [`Client`] without using `Builder`, we recommend to only use in when you with to define a custom [`ClientConfig`] for the TLS connection.
///
/// [`Client`]: struct.Client
/// [`ClientConfig`]: https://docs.rs/rustls/0.15.2/rustls/struct.ClientConfig.html
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

    /// Vanilla (no-tls) connection to the designated host and port
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use std::result::Result;
    /// # use pop3_client::Builder;
    /// #
    /// # fn main() -> Result<(), String> {
    ///      let client = Builder::default().connect("my.host.com", 110)?;
    ///
    /// #    Ok(())
    /// # }
    /// ```
    /// # Errors
    /// The errors are defined by [`Client::connect()`] method.
    ///
    /// [`Client::connect()`]: struct.Client.html#method.connect
    #[cfg(not(feature = "with-rustls"))]
    pub fn connect(&mut self, host: &str, port: u16) -> Result<Client> {
        Client::connect_notls(host, port)
    }

    /// Connect to the designated host and port using TLS
    ///
    /// The usage is pretty much the same as in the no-tls option of connect().
    /// # Errors
    /// The errors are defined by [`Client::connect()`] method.
    ///
    /// [`Client::connect()`]: struct.Client.html#method.connect
    #[cfg(feature = "with-rustls")]
    pub fn connect(&mut self, host: &str, port: u16) -> Result<Client> {
        Client::connect_rustls(host, port, self.config.clone())
    }

    /// Define a custom config for the TLS connection
    ///
    /// # Example
    /// ```no_run
    /// # use std::result::Result;
    /// # use crate::Builder;
    ///   use rustls::ClientConfig;
    /// #
    /// # fn main() -> Result<(), String> {
    ///
    /// let config = ClientConfig::new().root_store
    ///     .add_server_trust_anchors(&webpki_roots::TLS_SERVER_ROOTS);
    ///
    /// let client = Builder::default().rustls_config(config).connect()?;
    /// #    Ok(())
    /// # }
    /// ```
    #[cfg(feature = "with-rustls")]
    pub fn rustls_config(&mut self, config: ClientConfig) -> &mut Self {
        self.config = Arc::new(config);
        self
    }
}

/// The key structure for the crate, delineating capabilities of the POP3 client as per the protocol [RFC]
///
/// # Errors and problems
/// **All** the methods this `Client` has are susceptible to errors. The common reasons for those are:
/// - Not possible to establish connection
/// - The server does not support the protocol
/// - Connection aborted
/// - Some data got lost or modified, and now it's not possible to decode the obtained message
/// - The server does not recognize the command. This might happen even if by [RFC], the command is mandatory, as most of the servers do not follow the protocol letter by letter
/// - The command was sent on the wrong stage. In other words, you tried to do something before you authorized.
/// - The server returned an error response. We'll look at those within each separate method
///
/// To find out more, read the output of the error you've got -- it's always a string!
///
/// [RFC]: https://tools.ietf.org/html/rfc1081
pub struct Client {
    #[cfg(feature = "with-rustls")]
    client: BufReader<StreamOwned<ClientSession, TcpStream>>,
    #[cfg(not(feature = "with-rustls"))]
    client: BufReader<TcpStream>,
    authorized: bool,
}

impl Client {
    /// Connect to given host and port.
    ///
    /// This is the simplest way to initiate connection, so it's preferable to use it in a straightforward manner unless you have specific [`ClientConfig`] reservations.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use std::result::Result;
    /// # use pop3_client::Client;
    /// #
    /// # fn main() -> Result<(), String> {
    ///let client = Client::connect("my.host.com", 110)?;
    ///
    /// #    Ok(())
    /// # }
    /// ```
    ///
    /// [`ClientConfig`]: https://docs.rs/rustls/0.15.2/rustls/struct.ClientConfig.html
    pub fn connect(host: &str, port: u16) -> Result<Self> {
        Builder::default().connect(host, port)
    }

    /// Authorization through plaintext login and password
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use std::result::Result;
    /// # use pop3_client::Client;
    /// #
    /// # fn main() -> Result<(), String> {
    /// # let mut client = Client::connect("my.host.com", 110)?;
    /// client.login("sweet_username", "very_secret_password")?;
    /// #    Ok(())
    /// # }
    /// ```
    /// # Errors
    /// The server may return an error response if:
    /// - the username was not found
    /// - the password does not match the username
    /// - the connection to this mailbox has been locked by another device -- so you won't be able to connect until the lock is released.
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

    /// End the session, consuming the client
    ///
    /// # Example
    ///
    /// ```compile_fail
    /// # use std::result::Result;
    /// #
    /// # use pop3_client::Client;
    /// # fn main() -> Result<(), String> {
    /// # let mut client = Client::connect("my.host.com", 110)?;
    ///client.quit()?;
    ///client.noop()?; // Shouldn't compile, as the client has been consumed upon quitting
    /// #    Ok(())
    /// # }
    /// ```
    pub fn quit(mut self) -> Result<()> {
        self.send("QUIT\r\n", false).map(|_| ())
    }

    /// Display the statistics for the mailbox (that's what the `STAT` command does).
    ///
    /// In the resulting u32 tuple, the first number is the number of messages, and the second one is number of octets in those messages.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use std::result::Result;
    /// #
    /// # use pop3_client::Client;
    /// # fn main() -> Result<(), String> {
    /// # let mut client = Client::connect("my.host.com", 110)?;
    /// let (messages, octets) = client.stat()?;
    /// assert_eq!(messages, 2);
    /// assert_eq!(octets, 340);
    /// #    Ok(())
    /// # }
    /// ```
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

    /// Show the statistical information on a chosen letter, or all letters. The information in question always required to start with the letter size, but use of additional stats is not regimented in any way.
    ///
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use std::result::Result;
    /// #
    /// # use pop3_client::Client;
    /// # fn main() -> Result<(), String> {
    /// # let mut client = Client::connect("my.host.com", 110)?;
    /// let single_stats = client.list(Some(1))?; // show info on the letter number 1
    /// let all_stats = client.list(None)?; // show info on all letters
    ///
    /// #    Ok(())
    /// # }
    /// ```
    /// # Errors
    /// The server may return an error response if:
    /// - The letter under the given index does not exist in the mailbox
    /// - The letter under the given index has been marked deleted
    pub fn list(&mut self, msg: Option<u32>) -> Result<String> {
        let query = if let Some(num) = msg {
            format!("LIST {}\r\n", num)
        } else {
            "LIST\r\n".to_string()
        };
        self.send(&query, msg.is_none())
    }

    /// Show the full content of the chosen message
    ///
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use std::result::Result;
    /// #
    /// # use pop3_client::Client;
    /// # fn main() -> Result<(), String> {
    /// # let mut client = Client::connect("my.host.com", 110)?;
    /// let letter_content = client.retr(5)?;
    ///
    /// #    Ok(())
    /// # }
    /// ```
    /// # Errors
    /// The server may return an error response if:
    /// - The letter under the given index does not exist in the mailbox
    /// - The letter under the given index has been marked deleted
    pub fn retr(&mut self, msg: u32) -> Result<String> {
        let query = format!("RETR {}\r\n", msg);
        self.send(&query, true)
            .map(|s| s.split('\n').skip(1).collect::<Vec<&str>>().join("\n"))
    }


    /// Mark the chosen message as deleted
    ///
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use std::result::Result;
    /// #
    /// # use pop3_client::Client;
    /// # fn main() -> Result<(), String> {
    /// # let mut client = Client::connect("my.host.com", 110)?;
    /// client.dele(3)?; // now, the THIRD message is marked as deleted, and no new manipulations on it are possible
    ///
    /// #    Ok(())
    /// # }
    /// ```
    /// # Errors
    /// The server may return an error response if:
    /// - The letter under the given index does not exist in the mailbox
    /// - The letter under the given index has been marked deleted
    pub fn dele(&mut self, msg: u32) -> Result<String> {
        let query = format!("DELE {}\r\n", msg);
        self.send(&query, false)
    }


    /// Do nothing and return a positive response
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use std::result::Result;
    /// #
    /// # use pop3_client::Client;
    /// # fn main() -> Result<(), String> {
    /// # let mut client = Client::connect("my.host.com", 110)?;
    /// assert!(client.noop().is_ok());
    ///
    /// #    Ok(())
    /// # }
    /// ```
    pub fn noop(&mut self) -> Result<()> {
        self.send("NOOP\r\n", false).map(|_| ())
    }

    /// Reset the session state, unmarking the items marked as deleted
    ///
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use std::result::Result;
    /// #
    /// # use pop3_client::Client;
    /// # fn main() -> Result<(), String> {
    /// # let mut client = Client::connect("my.host.com", 110)?;
    /// client.dele(3)?;
    /// client.dele(4)?;
    /// client.rset()?; // undo all the previous deletions
    /// #    Ok(())
    /// # }
    /// ```
    pub fn rset(&mut self) -> Result<String> {
        self.send("RSET\r\n", false)
    }

    /// Show top n lines of a chosen message
    ///
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use std::result::Result;
    /// #
    /// # use pop3_client::Client;
    /// # fn main() -> Result<(), String> {
    /// # let mut client = Client::connect("my.host.com", 110)?;
    /// let top = client.top(1, 2)?; // Get TWO first lines of the FIRST message
    ///
    /// #    Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    /// The server may return an error response if:
    /// - The letter under the given index does not exist in the mailbox
    /// - The letter under the given index has been marked deleted
    pub fn top(&mut self, msg: u32, n: u32) -> Result<String> {
        let query = format!("TOP {} {}\r\n", msg, n);
        self.send(&query, true)
    }

    /// Show the unique ID listing for the chosen message or for all the messages. Unlike message numbering, this ID does not change between sessions.
    ///
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use std::result::Result;
    /// #
    /// # use pop3_client::Client;
    /// # fn main() -> Result<(), String> {
    /// # let mut client = Client::connect("my.host.com", 110)?;
    /// let uidl_all = client.uidl(None)?;
    /// let uidl_one = client.uidl(Some(1));
    ///
    /// #    Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    /// The server may return an error response if:
    /// - The letter under the given index does not exist in the mailbox
    /// - The letter under the given index has been marked deleted
    pub fn uidl(&mut self, msg: Option<u32>) -> Result<String> {
        let query = if let Some(num) = msg {
            format!("UIDL {}\r\n", num)
        } else {
            "UIDL\r\n".to_string()
        };
        self.send(&query, msg.is_none())
    }

    /// Authorise using the APOP method
    ///
    /// Refer to the POP3 [RFC] for details.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use std::result::Result;
    /// #
    /// # use pop3_client::Client;
    /// # fn main() -> Result<(), String> {
    /// # let mut client = Client::connect("my.host.com", 110)?;
    /// client.apop("another_sweet_username", "c4c9334bac560ecc979e58001b3e22fb")?;
    ///
    /// #    Ok(())
    /// # }
    /// ```
    /// # Errors
    /// The server will return error if permission was denied.
    ///
    /// [RFC]: https://tools.ietf.org/html/rfc1081
    pub fn apop(&mut self, name: &str, digest: &str) -> Result<String> {
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
