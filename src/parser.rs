use std::{fmt::{Display, Formatter}, error::Error};

use pktparse;
use dns_parser;
use tls_parser;

#[derive(Debug)]
enum ParsingError {
    GenericError(String),
    ArpParsingError,
    EthernetParsingError,
    IpParsingError,
    TcpParsingError,
    UdpParsingError
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
            }
        }       
    }
}

impl Error for ParsingError {}


/*
    In this mod are l
 */
mod packet {
    use super::{protocols::Protocols, ParsingError};


    pub struct PacketInfo{
        id: isize,
        mac_src: Option<String>,
        mac_dst: Option<String>,
        ip_src: Option<String>,
        ip_dst: Option<String>,
        port_src: Option<u16>,
        port_dst: Option<u16>,
        protocol: Protocols,
        length: usize,
        timestamp: f64
    }

    

    impl PacketInfo {

        pub fn new(length: usize, timestamp: f64) -> Self {
            PacketInfo { id: -1,  mac_src: None, mac_dst: None, ip_src: None, ip_dst: None, port_src: None, port_dst: None, protocol: Protocols::Ethernet , length, timestamp }
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

        pub fn get_id(&self) -> isize {
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
    use super::packet::{PacketInfo};

    use super::ParsingError;

    #[derive(Clone, Copy)]
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
    fn mac_address_to_string(mac: MacAddress) -> String{
        let mut string_res = String::new();

        for val in mac.0 {
            string_res = string_res + ":" + &val.to_string()
        }

        string_res.remove(string_res.len() - 1);

        string_res
    }

    /*
        Parse ethernet layer, 
        in the PacketInfo object it updates the
            - mac_src
            - mac_dst 
        fields 
     */
    fn parse_ethernet<'a>(packet_info: & mut PacketInfo, data: & 'a [u8]) -> Result<(& 'a [u8], EthernetFrame), ParsingError> {
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

                Ok((remaining, ipv6_head))
            },
            Err(_) => {
                Err(ParsingError::IpParsingError)
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
}