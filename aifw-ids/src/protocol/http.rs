use crate::flow::{Flow, FlowDirection};

use super::{AppProto, ParseResult, ProbeResult, ProtocolParser, StickyBuffers};

/// HTTP/1.x parser — extracts method, URI, host, user-agent, etc.
/// Uses `httparse` for zero-allocation header parsing.
pub struct HttpParser;

/// Known HTTP methods for quick detection
const HTTP_METHODS: &[&[u8]] = &[
    b"GET ",
    b"POST ",
    b"PUT ",
    b"DELETE ",
    b"HEAD ",
    b"OPTIONS ",
    b"PATCH ",
    b"CONNECT ",
    b"TRACE ",
];

impl ProtocolParser for HttpParser {
    fn name(&self) -> &str {
        "http"
    }

    fn app_proto(&self) -> AppProto {
        AppProto::Http
    }

    fn default_ports(&self) -> &[u16] {
        &[80, 8080, 8000, 8888, 3000]
    }

    fn probe(&self, payload: &[u8], direction: FlowDirection) -> ProbeResult {
        if payload.len() < 4 {
            return ProbeResult::NeedMore;
        }

        match direction {
            FlowDirection::ToServer => {
                // Check for HTTP method
                for method in HTTP_METHODS {
                    if payload.starts_with(method) {
                        return ProbeResult::Match;
                    }
                }
                ProbeResult::NoMatch
            }
            FlowDirection::ToClient => {
                // Check for HTTP response
                if payload.starts_with(b"HTTP/") {
                    ProbeResult::Match
                } else {
                    ProbeResult::NoMatch
                }
            }
        }
    }

    fn parse(
        &self,
        _flow: &mut Flow,
        payload: &[u8],
        direction: FlowDirection,
        buffers: &mut StickyBuffers,
    ) -> ParseResult {
        match direction {
            FlowDirection::ToServer => self.parse_request(payload, buffers),
            FlowDirection::ToClient => self.parse_response(payload, buffers),
        }
    }
}

impl HttpParser {
    fn parse_request(&self, payload: &[u8], buffers: &mut StickyBuffers) -> ParseResult {
        let mut headers = [httparse::EMPTY_HEADER; 64];
        let mut req = httparse::Request::new(&mut headers);

        match req.parse(payload) {
            Ok(httparse::Status::Complete(_)) | Ok(httparse::Status::Partial) => {
                if let Some(method) = req.method {
                    buffers.insert("http.method".into(), method.as_bytes().to_vec());
                }
                if let Some(path) = req.path {
                    buffers.insert("http.uri".into(), path.as_bytes().to_vec());
                    // Also set http.uri.raw for Suricata compat
                    buffers.insert("http.uri.raw".into(), path.as_bytes().to_vec());
                }

                for header in req.headers.iter() {
                    let name_lower = header.name.to_ascii_lowercase();
                    match name_lower.as_str() {
                        "host" => {
                            buffers.insert("http.host".into(), header.value.to_vec());
                        }
                        "user-agent" => {
                            buffers.insert("http.user_agent".into(), header.value.to_vec());
                        }
                        "content-type" => {
                            buffers.insert("http.content_type".into(), header.value.to_vec());
                        }
                        "cookie" => {
                            buffers.insert("http.cookie".into(), header.value.to_vec());
                        }
                        "referer" => {
                            buffers.insert("http.referer".into(), header.value.to_vec());
                        }
                        _ => {}
                    }
                    // All headers available as http.header
                    let key = format!("http.header.{}", name_lower);
                    buffers.insert(key, header.value.to_vec());
                }

                // Also store full request header blob
                buffers.insert("http.request_header".into(), payload.to_vec());

                ParseResult::Ok
            }
            Err(_) => ParseResult::Error("invalid HTTP request".into()),
        }
    }

    fn parse_response(&self, payload: &[u8], buffers: &mut StickyBuffers) -> ParseResult {
        let mut headers = [httparse::EMPTY_HEADER; 64];
        let mut resp = httparse::Response::new(&mut headers);

        match resp.parse(payload) {
            Ok(httparse::Status::Complete(body_offset)) => {
                if let Some(code) = resp.code {
                    buffers.insert("http.stat_code".into(), code.to_string().into_bytes());
                }
                if let Some(reason) = resp.reason {
                    buffers.insert("http.stat_msg".into(), reason.as_bytes().to_vec());
                }

                for header in resp.headers.iter() {
                    let name_lower = header.name.to_ascii_lowercase();
                    if name_lower == "content-type" {
                        buffers.insert("http.response_content_type".into(), header.value.to_vec());
                    }
                    if name_lower == "server" {
                        buffers.insert("http.server".into(), header.value.to_vec());
                    }
                }

                // Store response body if available
                if body_offset < payload.len() {
                    buffers.insert("http.response_body".into(), payload[body_offset..].to_vec());
                }

                ParseResult::Ok
            }
            Ok(httparse::Status::Partial) => {
                // Partial parse — extract what we can
                if let Some(code) = resp.code {
                    buffers.insert("http.stat_code".into(), code.to_string().into_bytes());
                }
                if let Some(reason) = resp.reason {
                    buffers.insert("http.stat_msg".into(), reason.as_bytes().to_vec());
                }
                ParseResult::Ok
            }
            Err(_) => ParseResult::Error("invalid HTTP response".into()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn test_probe_request() {
        let parser = HttpParser;
        assert_eq!(
            parser.probe(b"GET / HTTP/1.1\r\n", FlowDirection::ToServer),
            ProbeResult::Match
        );
        assert_eq!(
            parser.probe(b"POST /api HTTP/1.1\r\n", FlowDirection::ToServer),
            ProbeResult::Match
        );
        assert_eq!(
            parser.probe(b"\x16\x03\x01", FlowDirection::ToServer),
            ProbeResult::NeedMore // only 3 bytes, need at least 4
        );
    }

    #[test]
    fn test_probe_response() {
        let parser = HttpParser;
        assert_eq!(
            parser.probe(b"HTTP/1.1 200 OK\r\n", FlowDirection::ToClient),
            ProbeResult::Match
        );
    }

    #[test]
    fn test_parse_request() {
        let parser = HttpParser;
        let mut buffers: StickyBuffers = HashMap::new();

        let payload =
            b"GET /index.html HTTP/1.1\r\nHost: example.com\r\nUser-Agent: TestBot/1.0\r\n\r\n";
        let mut flow = test_flow();
        let result = parser.parse(&mut flow, payload, FlowDirection::ToServer, &mut buffers);

        assert!(matches!(result, ParseResult::Ok));
        assert_eq!(buffers.get("http.method").unwrap(), b"GET");
        assert_eq!(buffers.get("http.uri").unwrap(), b"/index.html");
        assert_eq!(buffers.get("http.host").unwrap(), b"example.com");
        assert_eq!(buffers.get("http.user_agent").unwrap(), b"TestBot/1.0");
    }

    #[test]
    fn test_parse_response() {
        let parser = HttpParser;
        let mut buffers: StickyBuffers = HashMap::new();

        let payload = b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nServer: Apache\r\n\r\n<html>";
        let mut flow = test_flow();
        let result = parser.parse(&mut flow, payload, FlowDirection::ToClient, &mut buffers);

        assert!(matches!(result, ParseResult::Ok));
        assert_eq!(buffers.get("http.stat_code").unwrap(), b"200");
        assert_eq!(buffers.get("http.server").unwrap(), b"Apache");
    }

    fn test_flow() -> Flow {
        use crate::decode::PacketProtocol;
        use crate::flow::FlowKey;
        let key = FlowKey::from_packet(
            "10.0.0.1".parse().unwrap(),
            "10.0.0.2".parse().unwrap(),
            1234,
            80,
            6,
        );
        let pkt = crate::decode::DecodedPacket {
            timestamp_us: 0,
            src_ip: Some("10.0.0.1".parse().unwrap()),
            dst_ip: Some("10.0.0.2".parse().unwrap()),
            src_port: Some(1234),
            dst_port: Some(80),
            protocol: PacketProtocol::Tcp,
            tcp_flags: None,
            payload: vec![],
            packet_len: 0,
        };
        Flow::new(key, &pkt, 65536)
    }
}
