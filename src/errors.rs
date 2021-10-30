use sentry::Level;

/// `ErrorHandler` manages errors received in the course of the program.
/// It will print them to stderr by default.
/// If a Sentry DSN is provided, `ErrorHandler` will log errors to Sentry
/// for further investigation.
#[derive(Clone)]
pub struct ErrorHandler {
    pub sentry_dsn: Option<String>,
}

impl ErrorHandler {
    pub fn error(&self, message: &str) {
        eprintln!("{}", message);
        match &self.sentry_dsn {
            Some(sentry_dsn) => {
                let _guard = sentry::init(sentry_dsn.as_str());
                sentry::capture_message(message, Level::Error);
            }
            None => {}
        }
    }
}
