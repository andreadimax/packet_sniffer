const { invoke } = window.__TAURI__.tauri;

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

await listen("devices_list", (event) => {
  console.log("js: devices_list: " + event)
  let devices_list = event.payload;

  let select = document.getElementById("select");

  for (const device in devices_list) {
    let option = document.createElement("option")
    button.innerHTML = device
    select.appendChild(option)
    
  }
})

window.greet = greet;
