use colored::*;
use pcap::{Device, Packet, PacketHeader};
use signal_hook::SigId;
use std::iter::Enumerate;
use std::sync::mpsc::{sync_channel, Receiver, RecvError, SyncSender, TryRecvError};
use std::sync::{Arc, Mutex};
use std::thread;

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

fn capture(dvc: String, tx: SyncSender<Message>, rx: Receiver<Message>) {
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

    t1.join().unwrap();
    parser_thread.join().unwrap();
}

fn main() {
    //sync channel used to send data between capture thread and parser thread
    let (tx, rx) = sync_channel(256);

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

    //user input
    let mut device_to_monitor = String::new();
    let mut dvc = String::new();

    'outer: loop {
        println!(
            "\nType the number of the device you want to monitor or {} to exit:",
            "quit".red()
        );
        device_to_monitor.clear();
        std::io::stdin().read_line(&mut device_to_monitor).unwrap();

        device_to_monitor = device_to_monitor.replace(LINE_ENDING, "");

        match device_to_monitor.as_str() {
            "quit" => {
                println!("Quitting...");
                return;
            }
            _ => match device_to_monitor.parse::<i32>() {
                Ok(val) => {
                    if val >= 0 {
                        dvc = String::from(&devices_list.get(val as usize).unwrap().name);
                        break 'outer;
                    }
                }
                Err(e) => {}
            },
        }

        println!("{}", "\nInvalid input! Retry...\n".red());
    }

    //let tx = tx.clone();
    capture(dvc, tx, rx);
}
