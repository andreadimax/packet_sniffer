use std::{fmt::{Display, Formatter}, error::Error};

use pktparse;
use dns_parser;
use tls_parser;

#[derive(Debug)]
enum ParsingError {
    GenericError(String)
}

impl ParsingError {
    pub fn new_generic_error(msg: &str) -> ParsingError {
        ParsingError::GenericError(String::from(msg))
    }
}

impl Display for ParsingError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::GenericError(error) => {
                write!(f, "Generic Error: {}", error)
            }
        }       
    }
}

impl Error for ParsingError {}



mod packets {
    use super::{protocols::Protocols, ParsingError};


    struct PacketInfo{
        mac_src: Option<String>,
        mac_dst: Option<String>,
        ip_src: Option<String>,
        ip_dst: Option<String>,
        port_src: Option<usize>,
        port_dst: Option<usize>,
        protocol: Protocols,
        length: usize,
        timestamp: f64
    }

    impl PacketInfo {

        pub fn new(length: usize, timestamp: f64) -> Self {
            PacketInfo { mac_src: None, mac_dst: None, ip_src: None, ip_dst: None, port_src: None, port_dst: None, protocol: Protocols::Ethernet , length, timestamp }
        }

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

        pub fn set_port_src(& mut self, port_src: usize) -> Result<(), ParsingError>{

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

        pub fn set_port_dst(& mut self, port_dst: usize) -> Result<(), ParsingError>{

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

         
    }

}

mod protocols {

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

    fn parse_ethernet(data: Vec<u8>) {

    }
}