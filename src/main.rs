use colored::*;
use packet_sniffer::connection::Connection;
use pcap::{Device, Packet, PacketHeader};
use signal_hook::SigId;
use std::error::Error;
use std::fmt::Display;
use std::io::{self, stdout, Write};
use std::iter::Enumerate;
use std::num::ParseIntError;
use std::sync::mpsc;
use std::sync::mpsc::{sync_channel, Receiver, RecvError, SyncSender, TryRecvError};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

enum Message {
    Device(String),
    Packet(Vec<u8>),
    PacketHeader(PacketHeader),
    Command(String), // resume and stop
}

enum InfoType {
    Data,
    Info,
    Error,
}

#[cfg(windows)]
const LINE_ENDING: &'static str = "\r\n";
#[cfg(not(windows))]
const LINE_ENDING: &'static str = "\n";

#[derive(Debug)]
enum ReadUserInputError {
    IOError(io::Error),
    InvalidInteger(ParseIntError),
    TimeIntervalMaxExceeded,
    TimeIntervalMinExceeded,
    AbsentDevice,
}
impl From<io::Error> for ReadUserInputError {
    fn from(e: io::Error) -> Self {
        Self::IOError(e)
    }
}
impl From<ParseIntError> for ReadUserInputError {
    fn from(e: ParseIntError) -> Self {
        Self::InvalidInteger(e)
    }
}
impl Error for ReadUserInputError {}

impl Display for ReadUserInputError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ReadUserInputError::InvalidInteger(_) => write!(f, "Input is not Valid"),
            ReadUserInputError::IOError(_) => write!(f, "Reading Input Error"),
            ReadUserInputError::AbsentDevice => write!(f, "There is not device for entered input"),
            ReadUserInputError::TimeIntervalMaxExceeded => write!(f, "Time interlval too big"),
            ReadUserInputError::TimeIntervalMinExceeded => write!(f, "Time interval too short"),
        }
    }
}

fn print_info(info: &str, info_type: InfoType) {
    match info_type {
        InfoType::Data => {
            println!("{}", info);
        }
        InfoType::Error => {
            println!("{} {}", "[ERR]".red(), info.red());
        }
        InfoType::Info => {
            println!("{} {}", "[INFO]".yellow(), info.yellow());
        }
    }
}

fn capture(dvc: String, tir: Duration, tx: SyncSender<Message>, rx: Receiver<Message>) {
    use packet_sniffer::packet::PacketInfo;
    use packet_sniffer::protocols::parse_packet;

    println!("\n ---- Capturing on device {} ---- \n", dvc.green());
    println!("\nType {} if you want to pause..\n", "stop".yellow());

    /*
        2 threads activated:
            - t2 used to monitor user input asynchronously
            - t1 used to perform the capture
            - the channel below is used to send user input between this 2 threads
    */
    let (send, rec) = sync_channel(1);
    let mut pause = false;

    //user input thread
    let _t2 = thread::spawn(move || loop {
        let mut buffer = String::new();
        std::io::stdin().read_line(&mut buffer).unwrap();
        send.send(buffer).unwrap();
    });

    /*
        A channel to communicate between parser_thread & report_thread
    */
    let (parser_tx, report_rx) = mpsc::channel();

    //capture thread
    let t1 = thread::spawn(move || {
        match pcap::Capture::from_device(dvc.as_str())
            .unwrap()
            .immediate_mode(true)
            .open()
        {
            Ok(mut cap) => {
                //Avoid blocking capture thread if no packet incoming..
                //Like using try_recv with channels
                cap = cap.setnonblock().unwrap();

                let cap = Arc::new(Mutex::new(cap));

                tx.send(Message::Device(dvc)).unwrap();
                loop {
                    //check if there's a new input from user

                    if pause == false {
                        match rec.try_recv() {
                            Ok(key) => {
                                let command = key.trim();
                                match command {
                                    "stop" => {
                                        print_info(
                                            "Capture stopped. Type 'resume' to restart.",
                                            InfoType::Info,
                                        );
                                        pause = true;
                                        tx.send(Message::Command(String::from(command))).unwrap();
                                    }
                                    "resume" => {
                                        print_info("Capture resumed", InfoType::Info);
                                        pause = false;
                                        tx.send(Message::Command(String::from(command))).unwrap();
                                    }
                                    "quit" => {
                                        println!("Quitting...");
                                        break;
                                    }
                                    _ => println!("Wrong command"),
                                }
                            }
                            Err(TryRecvError::Empty) => (),
                            Err(TryRecvError::Disconnected) => panic!("Channel disconnected"),
                        }
                    } else {
                        match rec.try_recv() {
                            Ok(key) => {
                                let command = key.trim();
                                match command {
                                    "stop" => {
                                        print_info(
                                            "Capture stopped. Type 'resume' to restart.",
                                            InfoType::Info,
                                        );
                                        pause = true;
                                        tx.send(Message::Command(String::from(command))).unwrap();
                                    }
                                    "resume" => {
                                        print_info("Capture resumed", InfoType::Info);
                                        pause = false;
                                        tx.send(Message::Command(String::from(command))).unwrap();
                                    }
                                    "quit" => {
                                        println!("Quitting...");
                                        break;
                                    }
                                    _ => println!("Wrong command"),
                                }
                            }
                            Err(TryRecvError::Empty) => (),
                            Err(TryRecvError::Disconnected) => panic!("Channel disconnected"),
                        }
                    }

                    let mut capp = cap.lock().unwrap();
                    let packet = capp.next();

                    //unfortunately Capture object does not support pause
                    //if we are in pause state we have to ignore packets
                    //but thread still runs...
                    if pause == false {
                        match packet {
                            Ok(packet) => {
                                tx.send(Message::PacketHeader(*packet.header)).unwrap();
                                tx.send(Message::Packet(packet.to_vec())).unwrap();
                            }
                            Err(_) => {}
                        }
                    }
                }
            }
            Err(e) => {
                println!(
                    "Error : {} on opening choosen interface. Quitting...",
                    e.to_string().red()
                )
            }
        }
    });

    let parser_thread = thread::spawn(move || {
        let mut counter: usize = 0;

        loop {
            let message = match rx.recv() {
                Ok(m) => m,
                _ => {
                    break;
                }
            };

            match message {
                Message::PacketHeader(ph) => {
                    let ts = format!("{}.{:06}", &ph.ts.tv_sec, &ph.ts.tv_usec)
                        .parse::<f64>()
                        .unwrap();
                    let mut packet = PacketInfo::new(ph.caplen as usize, ts, counter);
                    counter += 1;

                    let message_1 = rx.recv().unwrap();

                    match message_1 {
                        Message::Packet(data) => match parse_packet(&mut packet, &data).err() {
                            Some(e) => {
                                print_info(
                                    &(format!("Packet {} - ", counter - 1) + &e.to_string()),
                                    InfoType::Error,
                                );
                            }
                            None => {
                                print_info(&packet.to_string(), InfoType::Data);
                                //Send packets to report thread
                                parser_tx.send(packet).unwrap();
                            }
                        },
                        _ => {
                            print_info(
                                "Error in parsing: Not received a packet after a packet header!",
                                InfoType::Error,
                            );
                        }
                    }
                }
                _ => {}
            }
        }
    });

    let report_thread = thread::spawn(move || {
        loop {
            //Thread may sleep longer than time interval -> Another solution is required
            thread::sleep(tir);
            println!("Report thread after sleep");
            //Collect all packets sent
            let packets: Vec<PacketInfo> = report_rx.iter().collect();
            //Gen PDF
            match Connection::get_report(&packets){
                Ok(_) => print_info("Report generation completed!", InfoType::Info),
                Err(_) => print_info("Error during report generation!", InfoType::Error),
            }
        }
    });

    report_thread.join().unwrap();
    t1.join().unwrap();
    parser_thread.join().unwrap();
}

fn main() {
    //sync channel used to send data between capture thread and parser thread
    let (tx, rx) = sync_channel(256);

    //Device to sniff
    let mut dvc = String::new();
    //ReportTime Interval - Default -> 5 secs
    let mut report_interval = Duration::new(5, 0);

    println!("> Welcome in PacketSniffer (Rust Edition) By A. Di Mauro, M.Basilico, M.L.Colangelo");

    'outer: loop {
        println!("> Select an option:\n-Search available devices (Type 'devices' or 'd');\n-Quit (Type 'quit' or 'q')");

        //Choice n.1 - Reading input
        let mut input = String::new();
        io::stdin().read_line(&mut input).unwrap();

        //Choice n.1 - Clearing input
        let mut new_input = input.trim().split_whitespace();
        let mut command = new_input.next().unwrap();

        //Choise n.1 - Matching input
        match command {
            "q" | "quit" => {
                println!("Quitting...");
                return;
            }
            comm => {
                match comm {
                    "devices" | "d" => {
                        match set_device() {
                            Ok(dvc_index) => {
                                dvc = dvc_index;
                            }
                            Err(_e) => {
                                print_info(
                                    "Device choiche went wrong. Please, retry!",
                                    InfoType::Error,
                                );
                                continue 'outer;
                            }
                        };
                    }
                    _ => {
                        print_info("Input does not recognized. Please, retry!", InfoType::Error);
                        break 'outer;
                    }
                };
            }
        };

        'inner: loop {
            //Choise n.2 - Time interval
            println!(
                "\n>Type the time interval(secs) after which you want a new reportor,{} or {} to restart, {} or {} to exit:",
                "restart".green(),
                "r".green(),
                "quit".red(),
                "q".red(),
            );

            //Choice n.2 - Reading input
            input.clear();
            io::stdin().read_line(&mut input).unwrap();

            //Choice n.2 - Clearing input
            new_input = input.trim().split_whitespace();
            command = new_input.next().unwrap();

            //Choise n.2 - Matching input
            match command {
                "q" | "quit" => {
                    println!("Quitting...");
                    return;
                }
                "r" | "restart" => {
                    println!("Restarting...");
                    continue 'outer;
                }
                comm => {
                    match set_time_interval(comm) {
                        Ok(time_interval) => {
                            report_interval = time_interval;
                            break 'outer;
                        }
                        Err(_e) => {
                            print_info(
                                "Time seems not to be correct. Please, retry!",
                                InfoType::Error,
                            );
                            continue 'inner;
                        }
                    };
                }
            }
        }
    }
    //let tx = tx.clone();
    capture(dvc, report_interval, tx, rx);
}

fn set_device() -> Result<String, ReadUserInputError> {
    //get devices list
    let devices_list = Device::list().unwrap();
    let mut counter: usize = 0;

    //printing devices list
    println!("\nAvailable devices:\n");

    for device in &devices_list {
        match &device.desc {
            Some(description) => {
                println!(
                    "{}) {} - {}",
                    counter,
                    &device.name,
                    String::from(description)
                );
            }
            None => {
                println!("{}) {} - No description available", counter, &device.name);
            }
        }
        counter += 1;
    }

    let mut device_to_monitor = String::new();
    //Device settings
    println!(">Type the number of the device you want to monitor");
    device_to_monitor.clear();
    std::io::stdin().read_line(&mut device_to_monitor)?;
    //Clear input
    let mut new_input = device_to_monitor.trim().split_whitespace();
    let command = new_input.next().unwrap();

    match command.parse::<i32>() {
        Ok(val) => {
            if val <= 0 || val >= counter.try_into().unwrap() {
                return Err(ReadUserInputError::AbsentDevice);
            } else {
                return Ok(String::from(&devices_list.get(val as usize).unwrap().name));
            }
        }
        Err(e) => return Err(ReadUserInputError::InvalidInteger(e)),
    }
}

fn set_time_interval(time_interval: &str) -> Result<Duration, ReadUserInputError> {
    //Parse time interval from string to u64
    match time_interval.parse::<u64>() {
        Ok(value) => match value {
            0..=29 => return Err(ReadUserInputError::TimeIntervalMinExceeded),
            3600..=std::u64::MAX => return Err(ReadUserInputError::TimeIntervalMaxExceeded),
            _ => return Ok(Duration::new(value, 0)),
        },
        Err(e) => return Err(ReadUserInputError::InvalidInteger(e)),
    }
}
