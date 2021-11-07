# DNS Cookie

RFC7873 left the construction of Server Cookies to the discretion of the DNS Server (implementer) which has resulted in a gallimaufry of different implementations. As a result, DNS Cookies are impractical to deploy on multi-vendor anycast networks, because the Server Cookie constructed by one implementation cannot be validated by another.

This crate is an implementation of [draft-sury-toorop-dnsop-server-cookies](https://datatracker.ietf.org/doc/html/draft-sury-toorop-dns-cookies-algorithms-00) which provides precise directions for creating Server and Client Cookies to address this issue.
