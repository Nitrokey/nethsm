type info = { 
  vendor : string ;
  product : string ;
  version : string ;
}[@@deriving yojson]

type state = [
 | `Unprovisioned
 | `Operational
 | `Locked
][@@deriving yojson]

let state_to_yojson state =
  `Assoc [ ("state", match state_to_yojson state with `List [l] -> l | _ -> assert false) ]

type system_info = { 
  firmwareVersion : string ;
  softwareVersion : string ;
  hardwareVersion : string ;
}[@@deriving yojson]

type t = {
  info : info ;
  system_info : system_info ;
  mutable state : state ;
}

let make = { 
  info = { vendor = "Nitrokey UG" ; product = "NitroHSM" ; version = "v1" } ;
  system_info = { firmwareVersion = "1" ; softwareVersion = "0.7rc3" ; hardwareVersion = "2.2.2" } ;
  state = `Unprovisioned ;
}

let info t = t.info
let system_info t = t.system_info
let state t = t.state

let provision t ~unlock ~admin time = t.state <- `Operational 

let reboot () = ()
let shutdown () = ()
let reset () = ()

