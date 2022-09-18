const { invoke, listen} = window.__TAURI__.tauri;

let greetInputEl;
let greetMsgEl;

window.addEventListener("DOMContentLoaded", () => {
  greetInputEl = document.querySelector("#greet-input");
  greetMsgEl = document.querySelector("#greet-msg");
});

async function greet() {
  // Learn more about Tauri commands at https://tauri.app/v1/guides/features/command
  greetMsgEl.textContent = await invoke("greet", { name: greetInputEl.value });
}

invoke("list_devices").then((event) => {
  console.log("js: devices_list: " + event)
  let devices_list = event;

  let select = document.getElementById("select");

  for (let index = 0; index < devices_list.length; index++) {
    let device = event[index]
    let option = document.createElement("option")
    option.innerHTML = device
    select.appendChild(option)
  }

 
})

window.greet = greet;
