use core::convert::TryFrom;
use core::hash::Hasher;
use siphasher::sip::SipHasher24;
use time::ext::NumericalDuration;
use time::{OffsetDateTime, UtcOffset};

const SERVER_COOKIE_LEN: usize = 16;

#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug)]
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

#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug)]
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
    client_cookie: [u8; 8],
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

#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug)]
pub struct Server {
    data: Data,
    hash: u64,
}

impl Server {
    pub fn new(
        version: Version,
        algorithm: Algorithm,
        reserved: u16,
        time: OffsetDateTime,
        client_cookie: [u8; 8],
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

    pub fn to_bytes(self) -> [u8; SERVER_COOKIE_LEN] {
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

    pub fn from_bytes(
        client_cookie: [u8; 8],
        server_cookie: &[u8],
        server_secrets: &[&[u8]],
    ) -> Result<Self, Error> {
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
        let mut server_cookie = None;
        for secret in server_secrets {
            let cookie = Self::new(version, algorithm, reserved, time, client_cookie, secret);
            if cookie.hash == hash {
                server_cookie = Some(cookie);
                break;
            }
        }
        match server_cookie {
            Some(cookie) => Ok(cookie),
            None => Err(Error::InvalidHash),
        }
    }

    pub fn valid(&self, time: OffsetDateTime) -> Result<(), Error> {
        let time = time.to_offset(UtcOffset::UTC);
        if self.data.time < time - 1.hours() {
            return Err(Error::Expired);
        } else if self.data.time > time + 5.minutes() {
            return Err(Error::TimeTravellor);
        }
        Ok(())
    }

    pub fn regenerate(mut self, time: OffsetDateTime, server_secret: &[u8]) -> Result<Self, Error> {
        let time = time.to_offset(UtcOffset::UTC);
        if self.data.time > time - 30.minutes() {
            return Ok(self);
        }
        self.data.time = time;
        self.hash = self.data.hash(server_secret);
        Ok(self)
    }
}

#[derive(Debug, Clone)]
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
