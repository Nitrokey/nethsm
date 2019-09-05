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

type t = {
  info : info ;
  state : state ;
}

let make = { 
  info = { vendor = "Nitrokey UG" ; product = "NitroHSM" ; version = "v1" } ;
  state = `Operational ;
}

let info t = t.info
let state t = t.state
