use colored::*;
use eventual::Timer;
use packet_sniffer::connection::Connection;
use pcap::{Device, PacketHeader};
use std::collections::HashMap;
use std::error::Error;
use std::fmt::Display;
use std::io::{self};
use std::num::ParseIntError;
use std::path::Path;
use std::sync::mpsc;
use std::sync::mpsc::{sync_channel, Receiver, SyncSender, TryRecvError};
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
    Info,
    Error,
}

#[derive(Debug)]
enum ReadUserInputError {
    IOError(io::Error),
    InvalidInteger(ParseIntError),
    TimeIntervalMaxExceeded,
    TimeIntervalMinExceeded,
    AbsentDevice,
    ReportPathError,
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
            ReadUserInputError::ReportPathError => write!(f, "Report path does not exist!"),
        }
    }
}

fn print_info(info: &str, info_type: InfoType) {
    match info_type {
        InfoType::Error => {
            println!("{} {}", "[ERR]".red(), info.red());
        }
        InfoType::Info => {
            println!("{} {}", "[INFO]".yellow(), info.yellow());
        }
    }
}

fn capture(
    dvc: String,
    tir: Duration,
    report_path: &str,
    tx: SyncSender<Message>,
    rx: Receiver<Message>,
) {
    use packet_sniffer::packet::PacketInfo;
    use packet_sniffer::protocols::parse_packet;

    println!("\n ---- Capturing on device {} ---- \n", dvc.green());

    //FILTRO
    let mut filter = String::new();

    let mut cap;

    loop {
        println!(
            "Type a filter if you want to apply it, press {} to start capturing or type {}/{} to exit:\n",
            "enter".green(),
            "quit".red(),
            "q".red()
        );
        println!("[The expression consists of one or more primitives. Primitives usually consist of an id (name or number) preceded by one or more qualifiers. \n\nThere are three different kinds of qualifier:\n-Type:  E.g., `host foo', `net 128.3', `port 20', `portrange 6000-6008'\n-Dir: E.g., `src foo', `dst net 128.3', `src or dst port ftp-data'\n-Proto: E.g., `ether src foo', `arp net 128.3', `tcp port 21', `udp portrange 7000-7009'.\n\nVisit {} for more]", "https://biot.com/capstats/bpf.html".blue());
        std::io::stdin().read_line(&mut filter).unwrap();
        filter = filter.trim().to_string();
        cap = pcap::Capture::from_device(dvc.as_str())
            .unwrap()
            .immediate_mode(true)
            .open();
        match cap {
            Ok(ref mut cap) => {
                if filter.is_empty() == false {
                    match cap.filter(&filter, false) {
                        Ok(()) => {
                            break;
                        }
                        Err(_e) => match filter.as_str() {
                            "quit" | "q" => return,
                            _ => {
                                filter.clear();
                                print_info("Error in filter syntax", InfoType::Error);
                            }
                        },
                    }
                } else {
                    break;
                }
            }
            Err(e) => {
                println!(
                    "Error : {} on opening choosen interface. Quitting...",
                    e.to_string().red()
                );
                return
            }
        }

    }
    println!("\nType {} if you want to pause..\n", "stop".yellow());

    /*
        2 threads activated:
            - t2 used to monitor user input asynchronously
            - t1 used to perform the capture
            - the channel below is used to send user input between this 2 threads
    */
    let (send, rec) = sync_channel(1);
    let mut pause = false;
    let path = report_path.to_string();

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

    /*
        A channel to communicate a request to generate a report
    */
    let (report_notification_tx, report_notification_rx) = mpsc::channel();
    //Define a timer to notify report thread
    let timer = Timer::new();
    let ticks = timer
        .interval_ms(tir.as_millis().try_into().unwrap())
        .iter();


    let report_notification_tx2 = report_notification_tx.clone();
    //capture thread
    let t1 = thread::spawn(move || {
        {
                    //Avoid blocking capture thread if no packet incoming..
                    //Like using try_recv with channels
                    let cap = cap.unwrap().setnonblock().unwrap();

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
                                            tx.send(Message::Command(String::from(command)))
                                                .unwrap();
                                        }
                                        "resume" => {
                                            print_info("Capture resumed", InfoType::Info);
                                            pause = false;
                                            tx.send(Message::Command(String::from(command)))
                                                .unwrap();
                                        }
                                        "quit" => {
                                            println!("Quitting...");
                                            println!("Waiting for the generation of the last report...");
                                            report_notification_tx2.send(true).expect(
                                                "Could not send signal on quitting channel.",
                                            );
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
                                            tx.send(Message::Command(String::from(command)))
                                                .unwrap();
                                        }
                                        "resume" => {
                                            print_info("Capture resumed", InfoType::Info);
                                            pause = false;
                                            tx.send(Message::Command(String::from(command)))
                                                .unwrap();
                                        }
                                        "quit" => {
                                            println!("Quitting...");
                                            println!("Waiting for the generation of the last report...");
                                            report_notification_tx2.send(true).expect(
                                                "Could not send signal on quitting channel.",
                                            );
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
                               // print_info(&packet.to_string(), InfoType::Data);

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
        //At the moment, it is not possible to read from the old pdf in order to retrieve old informations,
        //so, we must keep old packets to be able to collect info about them in new iterations
        //let mut packets: Vec<PacketInfo> = Vec::new();

        //Hashmap with Connections
        let mut connections : HashMap<(String, Option<u16>, String, Option<u16>), Connection> = HashMap::new();


        loop {
            //Check report notification received
            match report_notification_rx.recv() {
                Ok(quit) => {

                    //Collect all packets sent -> Try_iter does not block the thread waiting other packets
                    let new_packets: Vec<PacketInfo> = report_rx.try_iter().collect();
                    //Check at least one new packet is available otherwise we can avoid to gen a new report
                    //(The program is probably paused)
                    if new_packets.is_empty() && !quit {
                        //print_info("No new packages. The latest report is already up to date!", InfoType::Info);
                        continue;
                    }else if new_packets.is_empty() && quit {
                    //If no new packets are available and there was a request to quit, no report will be generated
                        print_info("No new packages. The latest report is already up to date!", InfoType::Info);
                        break;
                    }

                    //NEW PACKETS AVAILABLE
                    //GENERATE PDF
                    match Connection::get_report(&mut connections, &new_packets, &path) {
                        Ok(_) => print_info("Report generation completed!", InfoType::Info),
                        Err(e) => print_info(&(format!("{}", &e.to_string())), InfoType::Error),
                    }

                    if quit {
                        break;
                    }

                }
                Err(_) => {}
            }
        }
    });

    /*
    Main thread notify report thread any report_interval 
    */
    for _ in ticks {
        match report_notification_tx.send(false){
            Ok(_) => {},
            Err(_) => break,
        }
    }

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
    //Path for report
    let mut report_path = String::new();

    println!("\n> Welcome in PacketSniffer (Rust Edition) By A.Di Mauro, M.Basilico, M.L.Colangelo\n");

    'outer: loop {
        println!("> Select an option:\n-Search available devices (Type 'devices' or 'd');\n-Quit (Type 'quit' or 'q')");

        //Choice n.1 - Reading input
        let mut input = String::new();
        io::stdin().read_line(&mut input).unwrap();

        //Choice n.1 - Clearing input
        let mut new_input = input.trim().split_whitespace();
        let mut command = new_input.next().unwrap_or("");

        //Choise n.1 - Matching input
        match command {
            "q" | "quit" => {
                println!("Quitting...");
                return;
            }
            comm => {
                match comm {
                    "devices" | "d" => loop {
                        match set_device() {
                            Ok(dvc_index) => {
                                dvc = dvc_index;
                                break;
                            }
                            Err(_e) => {
                                print_info(
                                    "Device choiche went wrong. Please, retry!",
                                    InfoType::Error,
                                );
                                continue;
                            }
                        };
                    },
                    _ => {
                        print_info("Input does not recognized. Please, retry!", InfoType::Error);
                        continue 'outer;
                    }
                };
            }
        };

        'inner: loop {
            //Choise n.2 - Time interval
            println!(
                "\n>Type the time interval(secs) after which you want a new report (minimum 5 secs), {} or {} to restart, {} or {} to exit:",
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
            command = new_input.next().unwrap_or("");

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
                            break;
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

        'inner2: loop {
            //Choise n.3 - Report Path
            println!(
                "\n>Type the path where you want a new report or {}/{} to restart or {}/{} to exit:\n{}",
                "restart".green(),
                "r".green(),
                "quit".red(),
                "q".red(),
                "(Do not type anything if you want use current directory)".yellow()
            );

            //Choice n.3 - Reading input
            input.clear();
            io::stdin().read_line(&mut input).unwrap();

            //Choice n.3 - Clearing input
            new_input = input.trim().split_whitespace();
            command = new_input.next().unwrap_or("");

            //Choise n.3 - Matching input
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
                    match set_report_path(comm) {
                        Ok(s) => {
                            report_path = String::from(s);
                            break 'outer;
                        }
                        Err(_e) => {
                            print_info("Path does not exist. Please, retry!", InfoType::Error);
                            continue 'inner2;
                        }
                    };
                }
            }
        }
    }
    //let tx = tx.clone();
    capture(dvc, report_interval, &report_path, tx, rx);
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
    let command = new_input.next().unwrap_or("");

    match command.parse::<i32>() {
        Ok(val) => {
            if val < 0 || val >= counter.try_into().unwrap() {
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
            0..=4 => return Err(ReadUserInputError::TimeIntervalMinExceeded),
            3600..=std::u64::MAX => return Err(ReadUserInputError::TimeIntervalMaxExceeded),
            _ => return Ok(Duration::new(value, 0)),
        },
        Err(e) => return Err(ReadUserInputError::InvalidInteger(e)),
    }
}

fn set_report_path(path: &str) -> Result<String, ReadUserInputError> {
    //Check default case
    if path.trim().is_empty() {
        return Ok(path.to_string());
    }
    //Parse time interval from string to u64
    let new_path = Path::new(path);
    match new_path.is_dir() {
        true => return Ok(path.to_string()),
        false => return Err(ReadUserInputError::ReportPathError),
    }
}
