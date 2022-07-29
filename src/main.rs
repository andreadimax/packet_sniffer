use pcap::Device;

fn main() {
    
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
        std::io::stdin().read_line(& mut device_to_monitor).unwrap();

        device_to_monitor = device_to_monitor.replace("\n", "");
    
        match device_to_monitor.as_str() {
            "quit" => {
                println!("Quitting...");
                return
            },
            _ => {
                for device in &devices_list {
                    if device.name == device_to_monitor {
                        unimplemented!("still some months to work...");
                    }
                }
            }
        }
    }


}