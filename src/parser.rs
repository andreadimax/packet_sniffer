use std::{fmt::{Display, Formatter}, error::Error};

use pktparse;
use dns_parser;
use tls_parser;

#[derive(Debug)]
pub enum ParsingError {
    GenericError(String),
    ArpParsingError,
    EthernetParsingError,
    IpParsingError,
    TcpParsingError,
    UdpParsingError,
    IcmpParsingError,
    DnsParsingError,
    TlsParsingError
}

// impl ParsingError {
//     pub fn new_generic_error(msg: &str) -> ParsingError {
//         ParsingError::GenericError(String::from(msg))
//     }
// }

impl Display for ParsingError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::GenericError(error) => {
                write!(f, "Generic Error: {}", error)
            },
            Self::ArpParsingError => {
                write!(f, "Error in parsing arp packet")
            },
            Self::EthernetParsingError => {
                write!(f, "Error in parsing ethernet frame")
            },
            Self::IpParsingError => {
                write!(f, "Error in parsing ip header")
            },
            Self::TcpParsingError => {
                write!(f, "Error in parsing tcp header")
            },
            Self::UdpParsingError => {
                write!(f, "Error in parsing udp header")
            },
            Self::IcmpParsingError => {
                write!(f, "Error in parsing icmp header")
            },
            Self::DnsParsingError => {
                write!(f, "Error in parsing dns packet")
            },
            Self::TlsParsingError => {
                write!(f, "Error in parsing tls packet")
            }
        }       
    }
}

impl Error for ParsingError {}


mod packet {
    use super::{protocols::Protocols, ParsingError};


    pub struct PacketInfo{
        id: usize,
        mac_src: Option<String>,
        mac_dst: Option<String>,
        ip_src: Option<String>,
        ip_dst: Option<String>,
        port_src: Option<u16>,
        port_dst: Option<u16>,
        additional_info: Option<String>,
        protocol: Protocols,
        length: usize,
        timestamp: f64
    }

    

    impl PacketInfo {

        /*
            By default initial protocol is set as Ethernet
         */
        pub fn new(length: usize, timestamp: f64, id: usize) -> Self {
            PacketInfo { id,  mac_src: None, mac_dst: None, ip_src: None, ip_dst: None, port_src: None, port_dst: None, additional_info: None, protocol: Protocols::Ethernet , length, timestamp }
        }

        /* ---------- SETTERS ---------- */
        /* ----------------------------- */

        /*
            In some setter is checked that
            every field is set only 1 time
            It has no sense to change the 
            ip address of a packet...
         */

        pub fn set_mac_src(& mut self, mac_src: &str) -> Result<(), ParsingError>{

            match &self.mac_src {
                Some(_) => {
                    Err(ParsingError::GenericError("trying to set an already present mac src".to_string()))
                },
                None => {
                    self.mac_src = Some(String::from(mac_src));
                    Ok(())
                }
            }
        }

        pub fn set_mac_dst(& mut self, mac_dst: &str) -> Result<(), ParsingError>{

            match &self.mac_dst {
                Some(_) => {
                    Err(ParsingError::GenericError("trying to set an already present mac dst".to_string()))
                },
                None => {
                    self.mac_dst = Some(String::from(mac_dst));
                    Ok(())
                }
            }
        }

        pub fn set_ip_src(& mut self, ip_src: &str) -> Result<(), ParsingError>{

            match &self.ip_src {
                Some(_) => {
                    Err(ParsingError::GenericError("trying to set an already present ip src".to_string()))
                },
                None => {
                    self.ip_src = Some(String::from(ip_src));
                    Ok(())
                }
            }
        }

        pub fn set_ip_dst(& mut self, ip_dst: &str) -> Result<(), ParsingError>{

            match &self.ip_dst {
                Some(_) => {
                    Err(ParsingError::GenericError("trying to set an already present ip dst".to_string()))
                },
                None => {
                    self.ip_dst = Some(String::from(ip_dst));
                    Ok(())
                }
            }
        }

        pub fn set_port_src(& mut self, port_src: u16) -> Result<(), ParsingError>{

            match &self.port_src {
                Some(_) => {
                    Err(ParsingError::GenericError("trying to set an already present port src".to_string()))
                },
                None => {
                    self.port_src = Some(port_src);
                    Ok(())
                }
            }
        }

        pub fn set_port_dst(& mut self, port_dst: u16) -> Result<(), ParsingError>{

            match &self.port_dst {
                Some(_) => {
                    Err(ParsingError::GenericError("trying to set an already present port dst".to_string()))
                },
                None => {
                    self.port_dst = Some(port_dst);
                    Ok(())
                }
            }
        }

        pub fn set_info(& mut self, additional_info: &str){
            self.additional_info = Some(String::from(additional_info));
        }

        pub fn set_protocol(& mut self, protocol: Protocols){
            self.protocol = protocol;
        }

        pub fn set_timestamp(& mut self, timestamp: f64){
            self.timestamp = timestamp;
        }

        pub fn set_length(& mut self, length: usize){
            self.length = length;
        }

        /* ----------------------------- */

        /* ---------- GETTERS ---------- */
        /* ----------------------------- */

        pub fn get_id(&self) -> usize {
            self.id
        }

        pub fn get_mac_src(&self) -> Option<&str>{
            match &self.mac_src {
                Some(mac_src) => {
                    Some(mac_src.as_str())
                },
                None => {
                    None
                }
            }
        }

        pub fn get_mac_dst(&self) -> Option<&str>{
            match &self.mac_dst {
                Some(mac_dst) => {
                    Some(mac_dst.as_str())
                },
                None => {
                    None
                }
            }
        }

        pub fn get_ip_src(&self) -> Option<&str>{
            match &self.ip_src {
                Some(ip_src) => {
                    Some(ip_src.as_str())
                },
                None => {
                    None
                }
            }
        }

        pub fn get_ip_dst(&self) -> Option<&str>{
            match &self.ip_dst {
                Some(ip_dst) => {
                    Some(ip_dst.as_str())
                },
                None => {
                    None
                }
            }
        }

        pub fn get_port_src(&self) -> Option<u16>{
            match self.port_src {
                Some(port_src) => {
                    Some(port_src)
                },
                None => {
                    None
                }
            }
        }

        pub fn get_port_dst(&self) -> Option<u16>{
            match self.port_dst {
                Some(port_dst) => {
                    Some(port_dst)
                },
                None => {
                    None
                }
            }
        }

        pub fn get_info(&self) -> Option<&str>{
            match &self.additional_info {
                Some(info) => {
                    Some(info)
                },
                None => None
            }
        }

        pub fn get_protocol(&self) -> Protocols {
            self.protocol
        }

        pub fn get_timestamp(&self) -> f64 {
            self.timestamp
        }

        pub fn get_length(&self) -> usize {
            self.length
        }

        /* ----------------------------- */

         
    }

}

mod protocols {
    use pktparse::ethernet::{self, EthernetFrame, MacAddress};
    use pktparse::ipv4::{self, IPv4Header};
    use pktparse::ipv6::{self, IPv6Header};
    use pktparse::arp::{self, ArpPacket};
    use pktparse::tcp::{self, TcpHeader};
    use pktparse::udp::{self, UdpHeader};
    use pktparse::icmp::{self, IcmpHeader, IcmpCode};
    use dns_parser::{self,Opcode};
    use tls_parser::{self,TlsMessage};
    use super::packet::{PacketInfo};

    use super::ParsingError;

    #[derive(Clone, Copy, PartialEq, Debug)]
    pub enum Protocols {
        Arp,
        Ethernet,
        IPv4,
        IPv6,
        Tcp,
        Udp,
        Icmp,
        Dns,
        Tls
    }

    /*
        Convert from defined type MacAddress
        to a string, easier to manage for 
        report
     */
    pub fn mac_address_to_string(mac: MacAddress) -> String{
        format!("{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}", mac.0[0], mac.0[1],mac.0[2],mac.0[3],mac.0[4],mac.0[5])
    }

    /*
        Parse ethernet layer, 
        in the PacketInfo object it updates the
            - mac_src
            - mac_dst 
        fields 
     */
    pub fn parse_ethernet<'a>(packet_info: & mut PacketInfo, data: & 'a [u8]) -> Result<(& 'a [u8], EthernetFrame), ParsingError> {
        let frame_res = ethernet::parse_ethernet_frame(data);
        
        match frame_res {

            Ok((remaining, eth_frame)) => {
                //updating fields
                packet_info.set_mac_src(mac_address_to_string(eth_frame.source_mac).as_str()) ?;
                packet_info.set_mac_dst(mac_address_to_string(eth_frame.dest_mac).as_str()) ?;

                Ok((remaining, eth_frame))
            },
            Err(_) => {
                Err(ParsingError::EthernetParsingError)
            }

        }
        
    }
    
    /*
        Parse arp packet, 
        in the PacketInfo object it updates the
            - mac_src
            - mac_dst 
            - ip_src
            - ip_dst
            - additional_info (with type of Arp operation)
        fields 
     */
    fn parse_arp<'a>(packet_info: & mut PacketInfo, data: & 'a [u8]) -> Result<(& 'a [u8], ArpPacket), ParsingError> {
        let frame_res = arp::parse_arp_pkt(data);
        
        match frame_res {

            Ok((remaining, arp_packet)) => {
                //updating fields
                packet_info.set_mac_src(mac_address_to_string(arp_packet.src_mac).as_str()) ?;
                packet_info.set_mac_dst(mac_address_to_string(arp_packet.dest_mac).as_str()) ?;
                packet_info.set_ip_src(arp_packet.src_addr.to_string().as_str()) ?;
                packet_info.set_ip_dst(arp_packet.dest_addr.to_string().as_str()) ?;
                packet_info.set_protocol(Protocols::Arp);

                match arp_packet.operation {
                    arp::Operation::Reply => {
                        packet_info.set_info("Arp Reply");
                    },
                    arp::Operation::Request =>{
                        packet_info.set_info("Arp Request");
                    },
                    arp::Operation::Other(_) => {
                        packet_info.set_info("Arp generic operation");
                    }
                }

                Ok((remaining, arp_packet))
            },
            Err(_) => {
                Err(ParsingError::EthernetParsingError)
            }

        }
        
    }

    /*
        Parse ipv4 layer, 
        in the PacketInfo object it updates the
            - ip_src
            - ip_dst 
        fields 
     */
    fn parse_ipv4<'a>(packet_info: & mut PacketInfo, data: & 'a [u8]) -> Result<(& 'a [u8], IPv4Header), ParsingError>{
        let ipv4_frame_res = ipv4::parse_ipv4_header(data);

        match ipv4_frame_res {

            Ok((remaining, ipv4_head)) => {
                //updating fields
                packet_info.set_ip_src(ipv4_head.source_addr.to_string().as_str()) ?;
                packet_info.set_ip_dst(ipv4_head.dest_addr.to_string().as_str()) ?;
                packet_info.set_protocol(Protocols::IPv4);

                packet_info.set_info("/");

                Ok((remaining, ipv4_head))
            },
            Err(_) => {
                Err(ParsingError::IpParsingError)
            }

        }
    }

    /*
        Parse ipv6 layer, 
        in the PacketInfo object it updates the
            - ip_src
            - ip_dst 
        fields 
     */
    fn parse_ipv6<'a>(packet_info: & mut PacketInfo, data: & 'a [u8]) -> Result<(& 'a [u8], IPv6Header), ParsingError>{
        let ipv4_frame_res = ipv6::parse_ipv6_header(data);

        match ipv4_frame_res {

            Ok((remaining, ipv6_head)) => {
                //updating fields
                packet_info.set_ip_src(ipv6_head.source_addr.to_string().as_str()) ?;
                packet_info.set_ip_dst(ipv6_head.dest_addr.to_string().as_str()) ?;
                packet_info.set_protocol(Protocols::IPv6);

                packet_info.set_info("/");

                Ok((remaining, ipv6_head))
            },
            Err(_) => {
                Err(ParsingError::IpParsingError)
            }

        }
    }

    /*
        Parse icmp packets, 
        in the PacketInfo object it updates the
            - additionl_info (with type of ICMP operation) 
        fields 
     */
    fn parse_icmp<'a>(packet_info: & mut PacketInfo, data: & 'a [u8]) -> Result<(& 'a [u8], IcmpHeader), ParsingError > {

        let icmp_frame_res = icmp::parse_icmp_header(data);

        match icmp_frame_res {

            Ok((remaining, icmp_header)) => {
                //updating fields
                packet_info.set_protocol(Protocols::Icmp);
                
                match icmp_header.code {
                    IcmpCode::DestinationUnreachable(_) => {
                        packet_info.set_info("ICMP Destination Unreachable")
                    },
                    IcmpCode::Redirect(_) => {
                        packet_info.set_info("ICMP Redirect")
                    },
                    IcmpCode::EchoReply => {
                        packet_info.set_info("ICMP Echo Reply")
                    },
                    IcmpCode::EchoRequest => {
                        packet_info.set_info("ICMP Echo Request")
                    },
                    IcmpCode::RouterAdvertisment => {
                        packet_info.set_info("ICMP Router Advertisment")
                    },
                    IcmpCode::RouterSolicication => {
                        packet_info.set_info("ICMP Router Solicitation")
                    },
                    IcmpCode::TimeExceeded(_) => {
                        packet_info.set_info("ICMP Time Exceeded")
                    },
                    _ => {
                        packet_info.set_info("ICMP Packet")
                    }
                }

                Ok((remaining, icmp_header))
            },
            Err(_) => {
                Err(ParsingError::IcmpParsingError)
            }

        }

    }

    /*
        Parse tcp layer, 
        in the PacketInfo object it updates the
            - port_src
            - port_dst 
        fields 
     */
    fn parse_tcp<'a>(packet_info: & mut PacketInfo, data: & 'a [u8]) -> Result<(& 'a [u8], TcpHeader ), ParsingError>{

        let tcp_frame_res = tcp::parse_tcp_header(data);

        match tcp_frame_res {

            Ok((remaining, tcp_header)) => {
                //updating fields
                packet_info.set_port_src(tcp_header.source_port) ?;
                packet_info.set_port_dst(tcp_header.dest_port) ?;
                packet_info.set_protocol(Protocols::Tcp);

                Ok((remaining, tcp_header))
            },
            Err(_) => {
                Err(ParsingError::IpParsingError)
            }

        }
    }

    /*
        Parse udp layer, 
        in the PacketInfo object it updates the
            - port_src
            - port_dst 
        fields 
     */
    fn parse_udp<'a>(packet_info: & mut PacketInfo, data: & 'a [u8]) -> Result<(& 'a [u8], UdpHeader ), ParsingError>{

        let udp_frame_res = udp::parse_udp_header(data);

        match udp_frame_res {

            Ok((remaining, udp_header)) => {
                //updating fields
                packet_info.set_port_src(udp_header.source_port) ?;
                packet_info.set_port_dst(udp_header.dest_port) ?;
                packet_info.set_protocol(Protocols::Udp);

                Ok((remaining, udp_header))
            },
            Err(_) => {
                Err(ParsingError::UdpParsingError)
            }

        }
    }

    /*
        Parse dns layer,
        in the PacketInfo object it updates the
            - additional_info (with type of the DNS operation)
        fields 
     */
    fn parse_dns<'a>(packet_info: & mut PacketInfo, data: & 'a [u8]) -> Result<(), ParsingError> {

        let dns_frame_res = dns_parser::Packet::parse(data);

        match dns_frame_res {
            Ok(packet) => {
                let code =  packet.header.opcode;
                let queries = packet.questions;

                packet_info.set_protocol(Protocols::Dns);

                match code {
                    Opcode::StandardQuery => {

                        let mut info = String::from("DNS Standard query for ");

                        //if it is a query put also query name in infos
                        for question in queries {
                            info = info + question.qname.to_string().as_str();
                        }

                        packet_info.set_info(&info);
                    },
                    Opcode::ServerStatusRequest => {
                        packet_info.set_info("DNS Server Status Request");
                    },
                    Opcode::InverseQuery => {
                        packet_info.set_info("DNS Inverse Query");
                    },
                    Opcode::Reserved(_) => {
                        packet_info.set_info("DNS Reserved");
                    }

                }

                Ok(())

            },
            Err(_) => {
                Err(ParsingError::DnsParsingError)
            }
        }
    }

    /*
        Parse dns layer,
        in the PacketInfo object it updates the
            - additional_info (with type of the DNS operation)
        fields 
     */
    fn parse_tls<'a>(packet_info: & mut PacketInfo, data: & 'a [u8]) -> Result<(), ParsingError> {

        let tls_frame_res = tls_parser::parse_tls_plaintext(data);

        match tls_frame_res {
            Ok((_body, header)) => {

                packet_info.set_protocol(Protocols::Tls);

                if let Some(tipo) = header.msg.get(0) {
                    match tipo {
                        TlsMessage::Handshake(_) => {
                            packet_info.set_info("TLS Handshake");
                        },
                        TlsMessage::ApplicationData(_) => {
                            packet_info.set_info("TLS Application Data");
                        },
                        TlsMessage::Heartbeat(_) => {
                            packet_info.set_info("TLS Heartbeat");
                        },
                        TlsMessage::ChangeCipherSpec => {
                            packet_info.set_info("TLS ChengeCipherSpec");
                        },
                        TlsMessage::Alert(_) => {
                            packet_info.set_info("TLS Alert");
                        }
                    }

                    Ok(())
                }
                else{
                    packet_info.set_info("/");
                    Ok(())
                }
            },
            Err(_) => {
                Err(ParsingError::TlsParsingError)
            }
        }
    }
}


#[cfg(test)]
mod test{
    use pktparse::ethernet::MacAddress;

    use super::{protocols::{mac_address_to_string, parse_ethernet, Protocols}, packet::PacketInfo, };

    /*
        TLS Packet example with following fields:
        -id:10
        -mac_src: A4:91:B1:AE:AA:C2
        -mac_dst: 5C:FB:3A:AC:88:7F
        -ip_src: 52.97.168.210
        -ip_dst: 192.168.1.164
        -length: 97
        -protocol: TLS
        -timestamp:3.735379
        -additional_info: TLS Application Data
     */
    static  tls_example_packet: [u8; 97] = 
        [0x5c, 0xfb, 0x3a, 0xac, 0x88, 0x7f, 0xa4, 0x91,
        0xb1, 0xae, 0xaa, 0xc2, 0x08, 0x00, 0x45, 0x00,
        0x00, 0x53, 0x79, 0x4f, 0x40, 0x00, 0xea, 0x06,
        0x77, 0xd5, 0x34, 0x61, 0xa8, 0xd2, 0xc0, 0xa8,
        0x01, 0xa4, 0x01, 0xbb, 0xc3, 0x00, 0x04, 0x04,
        0x82, 0x13, 0x62, 0xf7, 0xf8, 0xe6, 0x50, 0x18,
        0x40, 0x01, 0x12, 0x16, 0x00, 0x00, 0x17, 0x03,
        0x03, 0x00, 0x26, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x1f, 0xff, 0x8a, 0x0e, 0x75, 0xde,
        0x19, 0xb2, 0xbe, 0xf6, 0xd9, 0x97, 0x86, 0x34,
        0x5b, 0x7d, 0x42, 0x23, 0x53, 0x46, 0x9c, 0xc3,
        0x09, 0xa0, 0xd5, 0x5a, 0x84, 0x7f, 0x3d, 0xcf,
        0x50];

    


    #[test]
    fn test_mac_address_to_string(){

        let mac = MacAddress([12,219,223,144,224,82]);
        let mac_1 = MacAddress([0,219,223,144,224,82]);
        let mac_2 = MacAddress([9,219,223,144,224,82]);

        assert_eq!(mac_address_to_string(mac), "0C:DB:DF:90:E0:52");
        assert_eq!(mac_address_to_string(mac_1), "00:DB:DF:90:E0:52");
        assert_eq!(mac_address_to_string(mac_2), "09:DB:DF:90:E0:52");

    }

    #[test]
    fn test_parse_ethernet(){

        let mut packet_info = PacketInfo::new(97,3.735379,10);

        //Using example packet defined above
        parse_ethernet(&mut packet_info, &tls_example_packet).unwrap();

        assert_eq!(packet_info.get_id(), 10);
        assert_eq!(packet_info.get_length(), 97);
        assert_eq!(packet_info.get_protocol(), Protocols::Ethernet );
        assert_eq!(packet_info.get_timestamp(), 3.735379);
        assert_eq!(packet_info.get_mac_src(), Some("A4:91:B1:AE:AA:C2"));
        assert_eq!(packet_info.get_mac_dst(), Some("5C:FB:3A:AC:88:7F"));
        assert_eq!(packet_info.get_ip_src(), None);                         //ip fields should not be set yet
        assert_eq!(packet_info.get_ip_dst(), None);
    }
}