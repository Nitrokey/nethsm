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

type role = Administrator | Operator | Metrics | Backup
type user = { name : string ; password : string ; role : role }
type users = user list

type t = {
  info : info ;
  system_info : system_info ;
  mutable state : state ;
  users : users ;
}

let make () = { 
  info = { vendor = "Nitrokey UG" ; product = "NitroHSM" ; version = "v1" } ;
  system_info = { firmwareVersion = "1" ; softwareVersion = "0.7rc3" ; hardwareVersion = "2.2.2" } ;
  state = `Unprovisioned ;
  (* TODO these are dummies *)
  users = [ { name = "admin" ; password = "test1" ; role = Administrator } ; 
            { name = "operator" ; password = "test2" ; role = Operator } ] ;
}

let info t = t.info
let system_info t = t.system_info
let state t = t.state
let is_authenticated t ~username ~password =
  List.exists (fun u -> u.name = username && u.password = password) t.users
let is_authorized t username role =
  List.exists (fun u -> u.name = username && u.role = role) t.users

let provision t ~unlock:_ ~admin:_ _time = t.state <- `Operational 

let reboot () = ()
let shutdown () = ()
let reset () = ()

