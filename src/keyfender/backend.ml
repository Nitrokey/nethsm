type info = { 
  vendor : string ;
  product : string ;
  version : string ;
}[@@deriving yojson]


let info = { vendor = "Nitrokey UG" ; product = "NitroHSM" ; version = "v1" }
