type info = { 
  vendor : string ;
  product : string ;
  version : string ;
}[@@deriving yojson]

let info = { vendor = "Nitrokey UG" ; product = "NitroHSM" ; version = "v1" }

type state = [
 | `Unprovisioned
 | `Operational
 | `Locked
][@@deriving yojson]

let state_to_yojson state =
  `Assoc [ ("state", match state_to_yojson state with `List [l] -> l | _ -> assert false) ]

let state = `Operational

