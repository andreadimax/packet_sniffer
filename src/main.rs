use std::sync::{Arc, Mutex};
use pcap::{Device, PacketHeader};
use std::thread;
use std::sync::mpsc::{sync_channel, TryRecvError, SyncSender};
mod parser;


enum Message {
    Device(String),
    Packet(& 'static [u8]),
    PacketHeader(PacketHeader),
    Command(String) // resume and stop
}

fn capture(dvc: String, tx: SyncSender<Message>){

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
    let t2 = thread::spawn(move || loop {
        let mut buffer = String::new();
        std::io::stdin().read_line(&mut buffer).unwrap();
        send.send(buffer).unwrap();
    });

    //capture thread
    let t1 = thread::spawn(move || {

       let mut cap = pcap::Capture::from_device(dvc.as_str())
           .unwrap()
           .immediate_mode(true)
           .open()
           .unwrap();

       //let cap = Arc::new(Mutex::new(cap));


       tx.send(Message::Device(dvc)).unwrap();
        loop  {

            let packet_res = cap.next();

            //check if there's a new input from user
            match rec.try_recv() {
                Ok(key) => {
                    let command = key.trim();
                    match command {
                        "stop" => {
                            println!("Capture stopped. Type resume to restart.");
                            pause = true;
                            tx.send(Message::Command(String::from(command))).unwrap();
                        },
                        "resume" => {
                            println!("Capture resumed");
                            pause = false;
                            tx.send(Message::Command(String::from(command))).unwrap();
                        },
                        _ => println!("Wrong command")
                    }
                } ,
                Err(TryRecvError::Empty) => (),
                Err(TryRecvError::Disconnected) => panic!("Channel disconnected"),
            }

            //user typed "stop"
            if pause == false {
                //let mut cap = cap.lock().unwrap();
                
                match packet_res {
                    Ok(packet) => {
                        let packet_header = packet.header;
                        println!("{:?}", packet.header);
                        let packet = packet.to_owned();
                        tx.send(Message::Packet(packet.data)).unwrap();
                        tx.send(Message::PacketHeader(*packet_header)).unwrap()
                    },
                    Err(e) => {
                        println!("{}", format!("{:?}", e));
                        break;
                    }
                }
            }


        }

   });

  t1.join().unwrap();

}


fn main() {

    //sync channel used to send data between capture thread and parser thread
    let (tx, rx) = sync_channel(256);


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

    //user input
    let mut device_to_monitor = String::new();

    loop {
        println!("\nType the device you want to monitor or quit to exit:");
        device_to_monitor.clear();
        std::io::stdin().read_line(&mut device_to_monitor).unwrap();

        device_to_monitor = device_to_monitor.replace("\n", "");

        match device_to_monitor.as_str() {
            "quit" => {
                println!("Quitting...");
                return
            },
            _ => {
                for device in &devices_list {
                    if device.name == device_to_monitor {
                        let dvc = device_to_monitor.clone();
                        let tx = tx.clone();
                        capture(dvc, tx);

                    }
                }
            }
        }
    }
}