use failure::Error;
use lazy_static::lazy_static;
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
    client: TcpStream,
    state: Pop3ClientState,
}

// needed or not?
pub enum Pop3Result {
    Pop3Ok,
    Pop3Err,
}

impl Pop3Client {
    // establish TCP connection
    // then accept greeting (any positive response)
    pub fn connect(addr: impl Into<SocketAddr>) -> Self {
        Self {
            client: TcpStream::connect(addr).unwrap(),
            state: Pop3ClientState::Authorization,
        };
        unimplemented!()
    }

    // send with USER, PASS
    // accept result
    // if successful, move to Transaction state
    // if got negative answer -- check if connection is closed & reopen?
    pub fn login(&mut self, login: impl Into<String>, password: impl Into<String>) -> Pop3Result {
        unimplemented!()
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
    pub fn stat(&self) -> Pop3Result {
        unimplemented!()
    }

    // only Transaction state
    // can be OK then listing
    // or ERR if not
    // can be OK then CRLF if no messages
    pub fn list(&self, msg: Option<NonZeroU32>) -> Pop3Result {
        unimplemented!()
    }

    //only Transaction state
    // OK then multiline
    //or ERR
    // this is message retrieval
    pub fn retr(&self, msg: NonZeroU32) -> Pop3Result {
        unimplemented!()
    }

    // mark msg as deleted
    // OK or ERR
    //only TransactionState
    pub fn dele(&self, msg: NonZeroU32) -> Pop3Result {
        unimplemented!()
    }

    // transaction state only
    // only positive response
    pub fn noop(&self) -> Pop3Result {
        unimplemented!()
    }

    // Transaction state only
    // undeletes
    // only OK
    pub fn rset(&self) -> Pop3Result {
        unimplemented!()
    }

    // optional pop3 commands below

    // Show top n lines in message number msg
    // either OK and top of msg
    // or Err
    // transaction state only
    pub fn top(&self, msg: NonZeroU32, n: u32) -> Pop3Result {
        unimplemented!()
    }

    // unique id listing
    // transaction state only
    pub fn uidl(&self, msg: Option<NonZeroU32>) -> Pop3Result {
        unimplemented!()
    }

    // AUth stage only
    pub fn apop(&mut self, name: String, digest: String) -> Pop3Result {
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
