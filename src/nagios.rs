//! Minimal Nagios plugin result aggregation.
//!
//! Semantics mirror `github.com/nabeken/nagiosplugin/v2`: every result is
//! recorded, the worst status wins (`UNKNOWN` only if nothing else was
//! reported), and only the messages carrying the final status are printed.

use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Status {
    Ok = 0,
    Warning = 1,
    Critical = 2,
    Unknown = 3,
}

impl fmt::Display for Status {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Status::Ok => "OK",
            Status::Warning => "WARNING",
            Status::Critical => "CRITICAL",
            Status::Unknown => "UNKNOWN",
        })
    }
}

pub struct Check {
    name: &'static str,
    results: Vec<(Status, String)>,
    status: Status,
}

impl Check {
    pub fn new(name: &'static str) -> Self {
        Self {
            name,
            results: Vec::new(),
            status: Status::Unknown,
        }
    }

    pub fn add(&mut self, status: Status, message: impl Into<String>) {
        self.results.push((status, message.into()));
        // UNKNOWN yields to anything; otherwise the highest severity wins,
        // and a later UNKNOWN never overrides an existing status.
        if self.status == Status::Unknown || (status != Status::Unknown && status > self.status) {
            self.status = status;
        }
    }

    #[cfg(test)]
    pub fn status(&self) -> Status {
        self.status
    }

    /// Renders the single-line plugin output, e.g. `SMTP OK: 12ms response time`.
    pub fn render(&self) -> String {
        let msgs: Vec<&str> = self
            .results
            .iter()
            .filter(|(s, _)| *s == self.status)
            .map(|(_, m)| m.as_str())
            .collect();
        format!("{} {}: {}", self.name, self.status, msgs.join(", "))
    }

    /// Prints the result and terminates the process with the Nagios exit code.
    pub fn finish(mut self) -> ! {
        if self.results.is_empty() {
            self.add(Status::Unknown, "no check result specified");
        }
        println!("{}", self.render());
        std::process::exit(self.status as i32);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn worst_status_wins_and_only_its_messages_print() {
        let mut c = Check::new("SMTP");
        c.add(Status::Ok, "fast");
        c.add(Status::Warning, "slow");
        c.add(Status::Ok, "cert fine");
        assert_eq!(c.status(), Status::Warning);
        assert_eq!(c.render(), "SMTP WARNING: slow");
    }

    #[test]
    fn same_status_messages_are_joined() {
        let mut c = Check::new("SMTP");
        c.add(Status::Ok, "a");
        c.add(Status::Ok, "b");
        assert_eq!(c.render(), "SMTP OK: a, b");
    }

    #[test]
    fn unknown_never_overrides() {
        let mut c = Check::new("SMTP");
        c.add(Status::Critical, "boom");
        c.add(Status::Unknown, "huh");
        assert_eq!(c.status(), Status::Critical);
    }
}
