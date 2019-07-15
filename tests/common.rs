#[cfg(test)]
mod tests {
    use pop3_client::{Client, Result};

    #[cfg(not(feature = "with-rustls"))]
    fn connect() -> Result<Client> {
        Client::connect("pop3.mailtrap.io", 1100)
    }

    #[cfg(feature = "with-rustls")]
    fn connect() -> Result<Client> {
        pop3_client::Builder::default().connect("pop3.mailtrap.io", 1100)
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
        assert!(result.is_err());
        assert_ne!(result.unwrap_err(), "Connection aborted".to_owned())
    }

    #[test]
    fn login_wrong_password() {
        let mut client = connect().unwrap();
        let result = client.login("e913202b66b623", "1ddf1a9bd7fc4");
        eprintln!("wrong_password: {:?}", result);
        assert!(result.is_err());
        assert_ne!(result.unwrap_err(), "Connection aborted".to_owned())
    }

    #[test]
    fn login_wrong_stage() {
        let mut client = connect().unwrap();
        client.login("e913202b66b623", "1ddf1a9bd7fc45").ok();
        let result = client.login("e913202b66b623", "1ddf1a9bd7fc45");
        eprintln!("login_wrong_stage: {:?}", result);
        assert!(result.is_err());
        assert_ne!(result.unwrap_err(), "Connection aborted".to_owned())
    }

    // This test will fail if the server implementation does not comply to specification
    #[test]
    #[ignore]
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

    #[test]
    fn quit() {
        connect().unwrap().quit().unwrap()
    }

    #[test]
    fn stat_success() {
        let mut client = connect().unwrap();
        client.login("e913202b66b623", "1ddf1a9bd7fc45").ok();
        let result = client.stat();
        eprintln!("stat_success: {:?}", result);
        assert!(result.is_ok())
    }

    #[test]
    fn stat_wrong_stage() {
        let mut client = connect().unwrap();
        let result = client.stat();
        eprintln!("stat_wrong_stage: {:?}", result);
        assert!(result.is_err());
        assert_ne!(result.unwrap_err(), "Connection aborted".to_owned())
    }

    #[test]
    fn list_all() {
        let mut client = connect().unwrap();
        client.login("e913202b66b623", "1ddf1a9bd7fc45").ok();
        let result = client.list(None);
        eprintln!("list_all: {:?}", result);
        assert!(result.is_ok())
    }

    #[test]
    fn list_wrong_stage()
    {
        let mut client = connect().unwrap();
        let result = client.list(None);
        eprintln!("list_wrong_stage: {:?}", result);
        assert!(result.is_err());
        assert_ne!(result.unwrap_err(), "Connection aborted".to_owned())
    }

    #[test]
    fn retr_not_found()
    {
        let mut client = connect().unwrap();
        client.login("e913202b66b623", "1ddf1a9bd7fc45").ok();
        let result = client.retr(8);
        eprintln!("retr_not_found: {:?}", result);
        assert!(result.is_err());
        assert_ne!(result.unwrap_err(), "Connection aborted".to_owned())
    }

    #[test]
    fn retr_wrong_stage()
    {
        let mut client = connect().unwrap();
        let result = client.retr(10);
        eprintln!("retr_wrong_stage: {:?}", result);
        assert!(result.is_err());
        assert_ne!(result.unwrap_err(), "Connection aborted".to_owned())
    }

    #[test]
    fn dele_not_found()
    {
        let mut client = connect().unwrap();
        client.login("e913202b66b623", "1ddf1a9bd7fc45").ok();
        let result = client.dele(8);
        eprintln!("dele_not_found: {:?}", result);
        assert!(result.is_err());
        assert_ne!(result.unwrap_err(), "Connection aborted".to_owned())
    }

    #[test]
    fn dele_wrong_stage()
    {
        let mut client = connect().unwrap();
        let result = client.dele(10);
        eprintln!("dele_wrong_stage: {:?}", result);
        assert!(result.is_err());
        assert_ne!(result.unwrap_err(), "Connection aborted".to_owned())
    }

    #[test]
    fn noop_success()
    {
        let mut client = connect().unwrap();
        client.login("e913202b66b623", "1ddf1a9bd7fc45").ok();
        let result = client.noop();
        eprintln!("noop_success: {:?}", result);
        assert!(result.is_ok())
    }

    #[test]
    fn rset_all() {
        let mut client = connect().unwrap();
        client.login("e913202b66b623", "1ddf1a9bd7fc45").ok();
        let result = client.rset();
        eprintln!("rset_success: {:?}", result);
        assert!(result.is_ok())
    }

    #[test]
    fn rset_wrong_stage()
    {
        let mut client = connect().unwrap();
        let result = client.rset();
        eprintln!("rset_wrong_stage: {:?}", result);
        assert!(result.is_err());
        assert_ne!(result.unwrap_err(), "Connection aborted".to_owned())
    }


    #[test]
    fn top_not_found()
    {
        let mut client = connect().unwrap();
        client.login("e913202b66b623", "1ddf1a9bd7fc45").ok();
        let result = client.top(8, 3);
        eprintln!("top_not_found: {:?}", result);
        assert!(result.is_err());
        assert_ne!(result.unwrap_err(), "Connection aborted".to_owned())
    }

    #[test]
    fn top_wrong_stage()
    {
        let mut client = connect().unwrap();
        let result = client.top(10, 4);
        eprintln!("top_wrong_stage: {:?}", result);
        assert!(result.is_err());
        assert_ne!(result.unwrap_err(), "Connection aborted".to_owned())
    }

}
