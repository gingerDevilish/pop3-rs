#[cfg(test)]
mod tests {
    use pop3_client::{Client, Result};
    #[cfg(feature = "with-rustls")]
    use rustls::ClientConfig;

    #[cfg(not(feature = "with-rustls"))]
    fn connect() -> Result<Client> {
        Client::connect("pop3.mailtrap.io", 1100)
    }

    #[cfg(feature = "with-rustls")]
    fn connect() -> Result<Client> {

        let mut config = ClientConfig::new();
        config
            .root_store
            .add_server_trust_anchors(&webpki_roots::TLS_SERVER_ROOTS);

        pop3_client::Builder::default()
            .rustls_config(config)
            .connect("pop3.mailtrap.io", 9950)
    }

    #[test]
    fn connects() {
        assert!(connect().is_ok());
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
    // #[cfg(false)]
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
