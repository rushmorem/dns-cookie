//! RFC7873 left the construction of Server Cookies to the discretion
//! of the DNS Server (implementer) which has resulted in a gallimaufry
//! of different implementations.  As a result, DNS Cookies are
//! impractical to deploy on multi-vendor anycast networks, because the
//! Server Cookie constructed by one implementation cannot be validated
//! by another.
//!
//! This crate is an implementation of [draft-sury-toorop-dnsop-server-cookies] which provides precise
//! directions for creating Server and Client Cookies to address this issue.
//!
//! [draft-sury-toorop-dnsop-server-cookies]: https://datatracker.ietf.org/doc/html/draft-sury-toorop-dns-cookies-algorithms-00

#![cfg_attr(feature = "no-std-net", no_std)]
#![forbid(unsafe_code)]

use core::convert::TryFrom;
use core::fmt;
use core::hash::Hasher;
#[cfg(feature = "no-std-net")]
use no_std_net::IpAddr;
use siphasher::sip::SipHasher24;
#[cfg(not(feature = "no-std-net"))]
use std::net::IpAddr;
use time::ext::NumericalDuration;
use time::{OffsetDateTime, UtcOffset};

const SERVER_COOKIE_LEN: usize = 16;
const CLIENT_COOKIE_LEN: usize = 8;

/// Prescribes the structure and Hash calculation formula
#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug)]
#[must_use]
pub enum Version {
    One = 1,
}

impl TryFrom<u8> for Version {
    type Error = Error;

    fn try_from(version: u8) -> Result<Self, Self::Error> {
        match version {
            v if Version::One as u8 == v => Ok(Version::One),
            v => Err(Error::UnknownVersion(v)),
        }
    }
}

/// Defines what algorithm function to use for calculating the Hash
#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug)]
#[must_use]
pub enum Algorithm {
    SipHash24 = 4,
}

impl TryFrom<u8> for Algorithm {
    type Error = Error;

    fn try_from(algorithm: u8) -> Result<Self, Self::Error> {
        match algorithm {
            v if Algorithm::SipHash24 as u8 == v => Ok(Algorithm::SipHash24),
            1 => Err(Error::UnsupportedAlgorithm("FNV")),
            2 => Err(Error::UnsupportedAlgorithm("HMAC-SHA-256-64")),
            3 => Err(Error::UnsupportedAlgorithm("AES")),
            v => Err(Error::UnknownAlgorithm(v)),
        }
    }
}

#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug)]
struct Data {
    version: Version,
    algorithm: Algorithm,
    reserved: u16,
    time: OffsetDateTime,
    client_cookie: [u8; CLIENT_COOKIE_LEN],
}

impl Data {
    fn hash(&self, server_secret: &[u8]) -> u64 {
        match self.version {
            Version::One => match self.algorithm {
                Algorithm::SipHash24 => {
                    let mut hasher = SipHasher24::new();
                    hasher.write(&self.client_cookie);
                    hasher.write_u8(self.version as u8);
                    hasher.write_u8(self.algorithm as u8);
                    hasher.write_u16(self.reserved);
                    hasher.write_u32(self.time.unix_timestamp() as u32);
                    hasher.write(server_secret);
                    hasher.finish()
                }
            },
        }
    }
}

/// A 128-bit Server Cookie
#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug)]
#[must_use]
pub struct Server {
    data: Data,
    hash: u64,
}

impl Server {
    /// Creates a new server cookie
    pub fn new(
        version: Version,
        algorithm: Algorithm,
        reserved: u16,
        time: OffsetDateTime,
        client_cookie: [u8; CLIENT_COOKIE_LEN],
        server_secret: &[u8],
    ) -> Self {
        let data = Data {
            version,
            algorithm,
            reserved,
            client_cookie,
            time: time.to_offset(UtcOffset::UTC),
        };
        Self {
            data,
            hash: data.hash(server_secret),
        }
    }

    /// Regenerates a server cookie if the current cookie is more than 30 minutes old
    /// as prescribed by the draft
    pub fn regenerate(mut self, time: OffsetDateTime, server_secret: &[u8]) -> Self {
        let time = time.to_offset(UtcOffset::UTC);
        if self.data.time > time - 30.minutes() {
            return self;
        }
        self.data.time = time;
        self.hash = self.data.hash(server_secret);
        self
    }

    /// Creates and validates a server cookie from bytes
    pub fn decode(
        mut now: OffsetDateTime,
        client_cookie: [u8; CLIENT_COOKIE_LEN],
        server_cookie: &[u8],
        server_secrets: &[&[u8]],
    ) -> Result<Self, Error> {
        now = now.to_offset(UtcOffset::UTC);
        let cookie_len = server_cookie.len();
        if cookie_len != SERVER_COOKIE_LEN {
            return Err(Error::IncorrectLength(cookie_len));
        }
        let version = Version::try_from(server_cookie[0])?;
        let algorithm = Algorithm::try_from(server_cookie[1])?;
        let reserved = u16::from_be_bytes([server_cookie[2], server_cookie[3]]);
        let time = {
            let timestamp = u32::from_be_bytes([
                server_cookie[4],
                server_cookie[5],
                server_cookie[6],
                server_cookie[7],
            ]);
            OffsetDateTime::from_unix_timestamp(timestamp as i64).map_err(Error::TimestampRange)?
        };
        if time < now - 1.hours() {
            return Err(Error::Expired);
        } else if time > now + 5.minutes() {
            return Err(Error::TimeTravellor);
        }
        let hash = u64::from_be_bytes([
            server_cookie[8],
            server_cookie[9],
            server_cookie[10],
            server_cookie[11],
            server_cookie[12],
            server_cookie[13],
            server_cookie[14],
            server_cookie[15],
        ]);
        for secret in server_secrets {
            let cookie = Self::new(version, algorithm, reserved, time, client_cookie, secret);
            if cookie.hash == hash {
                return Ok(cookie);
            }
        }
        Err(Error::InvalidHash)
    }

    /// Converts a server cookie to bytes
    #[must_use]
    pub const fn encode(self) -> [u8; SERVER_COOKIE_LEN] {
        let reserved = self.data.reserved.to_be_bytes();
        let timestamp = (self.data.time.unix_timestamp() as u32).to_be_bytes();
        let hash = self.hash.to_be_bytes();
        [
            self.data.version as u8,
            self.data.algorithm as u8,
            reserved[0],
            reserved[1],
            timestamp[0],
            timestamp[1],
            timestamp[2],
            timestamp[3],
            hash[0],
            hash[1],
            hash[2],
            hash[3],
            hash[4],
            hash[5],
            hash[6],
            hash[7],
        ]
    }
}

/// A 64-bit Client Cookie
#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug)]
#[must_use]
pub struct Client {
    hash: u64,
}

impl Client {
    /// Creates a new client cookie
    pub fn new(
        version: Version,
        algorithm: Algorithm,
        client_ip: IpAddr,
        server_ip: IpAddr,
        client_secret: &[u8],
    ) -> Self {
        match version {
            Version::One => match algorithm {
                Algorithm::SipHash24 => {
                    let mut hasher = SipHasher24::new();
                    match client_ip {
                        IpAddr::V4(ip) => hasher.write(&ip.octets()),
                        IpAddr::V6(ip) => hasher.write(&ip.octets()),
                    }
                    match server_ip {
                        IpAddr::V4(ip) => hasher.write(&ip.octets()),
                        IpAddr::V6(ip) => hasher.write(&ip.octets()),
                    }
                    hasher.write(client_secret);
                    Self {
                        hash: hasher.finish(),
                    }
                }
            },
        }
    }

    /// Creates and validates a client cookie from bytes
    pub fn decode(
        version: Version,
        algorithm: Algorithm,
        client_ip: IpAddr,
        server_ip: IpAddr,
        client_cookie: [u8; CLIENT_COOKIE_LEN],
        client_secrets: &[&[u8]],
    ) -> Result<Self, Error> {
        let hash = u64::from_be_bytes(client_cookie);
        for secret in client_secrets {
            let cookie = Self::new(version, algorithm, client_ip, server_ip, secret);
            if cookie.hash == hash {
                return Ok(cookie);
            }
        }
        Err(Error::InvalidHash)
    }

    /// Converts a client cookie to bytes
    #[must_use]
    pub const fn encode(self) -> [u8; CLIENT_COOKIE_LEN] {
        self.hash.to_be_bytes()
    }
}

/// The errors returned by this crate
#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug)]
#[must_use]
pub enum Error {
    IncorrectLength(usize),
    TimestampRange(time::error::ComponentRange),
    InvalidHash,
    Expired,
    TimeTravellor,
    UnknownVersion(u8),
    UnknownAlgorithm(u8),
    UnsupportedAlgorithm(&'static str),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Error::IncorrectLength(len) => write!(f, "cookie has an incorrect length ({})", len),
            Error::TimestampRange(error) => write!(f, "{}", error),
            Error::InvalidHash => write!(f, "cookie has an invalid hash"),
            Error::Expired => write!(f, "cookie has expired"),
            Error::TimeTravellor => write!(f, "cookie has a timestamp from the future"),
            Error::UnknownVersion(version) => {
                write!(f, "cookie has an unknown version ({})", version)
            }
            Error::UnknownAlgorithm(algorithm) => {
                write!(f, "cookie has an unknown algorithm ({})", algorithm)
            }
            Error::UnsupportedAlgorithm(algorithm) => {
                write!(f, "cookie has an unsupported algorithm ({})", algorithm)
            }
        }
    }
}

#[cfg(not(feature = "no-std-net"))]
impl std::error::Error for Error {}
