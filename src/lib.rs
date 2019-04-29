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

enum Pop3ClientState {
    Authorization,
    Transaction,
    Update,
}

pub struct Pop3Client {
    client: BufReader<TcpStream>,
    state: Pop3ClientState,
}

type Pop3Result = Result<String, String>;

impl Pop3Client {
    pub fn connect(addr: impl Into<SocketAddr>) -> Option<Self> {
        TcpStream::connect(addr.into())
            .map(|client| Self {
                client: BufReader::new(client),
                state: Pop3ClientState::Authorization,
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

        let send_user = self
            .client
            .get_mut()
            .write_all(login_query.as_bytes())
            .map_err(|e| e.to_string());

        let send_pass = send_user.and_then(|_| self.read_response()).and_then(|s1| {
            let send_pass = self
                .client
                .get_mut()
                .write_all(password_query.as_bytes())
                .map_err(|e| e.to_string());
            send_pass.and_then(|_| self.read_response().map(|s2| format!("{}{}", s1, s2)))
        });

        if send_pass.is_ok() {
            self.state = Pop3ClientState::Transaction;
        }

        send_pass
    }

    // if sent from Authorization state
    // just send QUIT & get an ok response
    // enter the Update state?? (NO)
    //
    // if sent from Transaction state
    // enter the Update state
    // can be OK
    // or ERR if failed to remove all
    pub fn quit(&mut self) {
        unimplemented!()
    }

    // only from Transaction state
    // send STAT
    // accept positive + N-letters + N-octets
    pub fn stat(&mut self) -> Pop3Result {
        unimplemented!()
    }

    // only Transaction state
    // can be OK then listing
    // or ERR if not
    // can be OK then CRLF if no messages
    pub fn list(&mut self, msg: Option<NonZeroU32>) -> Pop3Result {
        unimplemented!()
    }

    //only Transaction state
    // OK then multiline
    //or ERR
    // this is message retrieval
    pub fn retr(&mut self, msg: NonZeroU32) -> Pop3Result {
        unimplemented!()
    }

    // mark msg as deleted
    // OK or ERR
    //only TransactionState
    pub fn dele(&mut self, msg: NonZeroU32) -> Pop3Result {
        unimplemented!()
    }

    // transaction state only
    // only positive response
    pub fn noop(&mut self) -> Pop3Result {
        unimplemented!()
    }

    // Transaction state only
    // undeletes
    // only OK
    pub fn rset(&mut self) -> Pop3Result {
        unimplemented!()
    }

    // optional pop3 commands below

    // Show top n lines in message number msg
    // either OK and top of msg
    // or Err
    // transaction state only
    pub fn top(&mut self, msg: NonZeroU32, n: u32) -> Pop3Result {
        unimplemented!()
    }

    // unique id listing
    // transaction state only
    pub fn uidl(&mut self, msg: Option<NonZeroU32>) -> Pop3Result {
        unimplemented!()
    }

    // AUth stage only
    pub fn apop(&mut self, name: String, digest: String) -> Pop3Result {
        unimplemented!()
    }

    // transmute a response into a result
    fn read_response(&mut self) -> Pop3Result {
        unimplemented!()
    }
}

enum Pop3Command {
    Greet,
    User,
}

//preferable response format
pub struct Pop3Response {
    code: u16,
    msg: String,
    data: Option<String>,
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
