#![cfg_attr(
    all(not(debug_assertions), target_os = "windows"),
    windows_subsystem = "windows"
)]

use std::sync::{Arc, Mutex};
use pcap::{Device, PacketHeader, Packet};
use tauri::Manager;
use std::thread;
use std::sync::mpsc::{sync_channel, TryRecvError, SyncSender, Receiver, RecvError};
mod parser;

enum Message{
    Device(String),
    Packet(Vec<u8>),
    PacketHeader(PacketHeader),
    Command(String) // resume and stop
}

#[cfg(windows)]
const LINE_ENDING: &'static str = "\r\n";
#[cfg(not(windows))]
const LINE_ENDING: &'static str = "\n";


fn capture(dvc: String, tx: SyncSender<Message>, rx: Receiver<Message>){

    use parser::packet::{PacketInfo};
    use parser::protocols::parse_packet;

    println!("Capturing on device {}..", dvc);
    println!("Type stop if you want to pause..");

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
    let t1 = thread::spawn(move    || {

       let mut cap = pcap::Capture::from_device(dvc.as_str())
           .unwrap()
           .immediate_mode(true)
           .open()
           .unwrap();

       cap = cap.setnonblock().unwrap();

       let cap = Arc::new(Mutex::new(cap));

       tx.send(Message::Device(dvc)).unwrap();
        loop  {

            //check if there's a new input from user

            //if capture is in progress don't block it, using try_recv
            if pause == false {
                match rec.try_recv() {
                    Ok(key) => {
                        let command = key.trim();
                        match command {
                            "stop" => {
                                println!("Capture stopped. Type 'resume' to restart.");
                                pause = true;
                                tx.send(Message::Command(String::from(command))).unwrap();
                            },
                            "resume" => {
                                println!("Capture resumed");
                                pause = false;
                                tx.send(Message::Command(String::from(command))).unwrap();
                            },
                            "quit" => {
                                println!("Quitting...");
                                break;
                            },
                            _ => println!("Wrong command")
                        }
                    } ,
                    Err(TryRecvError::Empty) => (),
                    Err(TryRecvError::Disconnected) => panic!("Channel disconnected"),
                }
            }
            //if capture not in progress we can use recv
            else{
                match rec.recv() {
                    Ok(key) => {
                        let command = key.trim();
                        match command {
                            "stop" => {
                                println!("Capture stopped. Type 'resume' to restart.");
                                pause = true;
                                tx.send(Message::Command(String::from(command))).unwrap();
                            },
                            "resume" => {
                                println!("Capture resumed");
                                pause = false;
                                tx.send(Message::Command(String::from(command))).unwrap();
                            },
                            "quit" => {
                                println!("Quitting...");
                                break;
                            },
                            _ => println!("Wrong command")
                        }
                    } ,
                    Err(RecvError) => panic!("Channel disconnected"),
                }
            }

            if pause == false {
                let mut cap = cap.lock().unwrap();
                let packet = cap.next();
                match packet {
                    Ok(packet) => {
                        tx.send(Message::PacketHeader(*packet.header)).unwrap();
                        tx.send(Message::Packet(packet.to_vec())).unwrap();
                    },
                    Err(_) => {
                    }
                }
            }


        }

   });

   let parser_thread = thread::spawn(move || {

        let mut counter: usize = 0;

        loop{
            let message = match rx.recv() {
                Ok(m) => {
                    m
                },
                _ => {
                    break;
                }
            };

            match message {
                Message::PacketHeader(ph) => {
                    let ts = format!("{}.{:06}",
                        &ph.ts.tv_sec, &ph.ts.tv_usec
                    ).parse::<f64>().unwrap();
                    let mut packet = PacketInfo::new(ph.caplen as usize, ts, counter);
                    counter += 1;

                    let message_1 = rx.recv().unwrap();

                    match message_1 {
                        Message::Packet(data) => {
                            match parse_packet(& mut packet, &data).err(){
                                Some(e) => {
                                    eprintln!("{}", e);
                                },
                                None => {
                                    println!("{}", packet);
                                }
                            }
                        },
                        _ => {
                            eprintln!("Error in parsing: Not received a packet after a packet header!");
                        }
                    }
                },
                _ => {

                }
            }
            
        }
    });


 



}

fn list_devices<R: tauri::Runtime>(manager: &impl Manager<R>){
    //get devices list
    let devices_list = Device::list().unwrap();

    let mut devices_vec = Vec::<String>::new();


    for device in &devices_list {
        match &device.desc {
            Some(description) => {
                devices_vec.push(format!("{} - {}", &device.name, String::from(description)));
            },
            None => {
                devices_vec.push(format!("{} - No description available", &device.name));
            }
        }
    }

    manager.emit_all("devices_list", devices_vec).unwrap();

}

fn main() {

    //sync channel used to send data between capture thread and parser thread
    let (tx, rx) = sync_channel(256);

    //user input
    let mut device_to_monitor = String::new();
    let mut dvc = String::new();

    //get devices list
    let devices_list = Device::list().unwrap();

    //printing devices list
    println!("Available devices:");

    for device in &devices_list {
        match &device.desc {
            Some(description) => {
                println!("{} - {}", &device.name, String::from(description));
            },
            None => {
                println!("{} - No description available", &device.name);
            }
        }
    }

    'outer:  loop {
        println!("\nType the device you want to monitor or quit to exit:");
        device_to_monitor.clear();
        std::io::stdin().read_line(&mut device_to_monitor).unwrap();

        device_to_monitor = device_to_monitor.replace(LINE_ENDING, "");

        match device_to_monitor.as_str() {
            "quit" => {
                println!("Quitting...");
                return
            },
            _ => {
                for device in &devices_list {
                    if device.name == device_to_monitor {
                        dvc = device_to_monitor.clone();
                        break 'outer;
                    }
                }
            }
        }
    }

    //let tx = tx.clone();
    capture(dvc, tx, rx);

    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![greet])
        .setup(|app| {
            let app_handle = app.handle();

            list_devices(&app_handle);

            Ok(())
        })
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}

// Learn more about Tauri commands at https://tauri.app/v1/guides/features/command
#[tauri::command]
fn greet(name: &str) -> String {
    format!("Hello, {}! You've been greeted from Rust!", name)
}
