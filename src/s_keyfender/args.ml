open Cmdliner
open Mirage_runtime_network.Arg

let docs = "KEYFENDER PARAMETERS"

let http_port =
  let doc =
    Arg.info ~docs ~docv:"PORT" ~doc:"Listening HTTP port." [ "http" ]
  in
  Mirage_runtime.register_arg Arg.(value & opt int 80 doc)

let https_port =
  let doc =
    Arg.info ~docs ~docv:"PORT" ~doc:"Listening HTTPS port." [ "https" ]
  in
  Mirage_runtime.register_arg Arg.(value & opt int 443 doc)

let platform =
  let doc = Arg.info ~docs ~docv:"IP" ~doc:"Platform IP." [ "platform" ] in
  let default_ip = Ipaddr.V4.of_string_exn "169.254.169.2" in
  Mirage_runtime.register_arg Arg.(value & opt ipv4_address default_ip doc)

let platform_port =
  let doc =
    Arg.info ~docs ~docv:"PORT" ~doc:"Platform port." [ "platform-port" ]
  in
  Mirage_runtime.register_arg Arg.(value & opt int 1023 doc)

let start =
  let doc =
    Arg.info ~docs ~doc:"Safeguard flag. Always required." [ "start" ]
  in
  Mirage_runtime.register_arg Arg.(value & flag doc)

let device_key =
  let doc =
    Arg.info ~docs ~docv:"DEVICE-KEY"
      ~doc:
        "Set the device key (Base64, only available if --no-platform is set to \
         true)"
      [ "device-key" ]
  in
  Mirage_runtime.register_arg Arg.(value & opt (some string) None doc)

let default_net =
  let doc =
    Arg.info ~docs ~docv:"DEFAULT-NET"
      ~doc:
        "Set the default network configuration. (Format: <ip>[/<mask>[;<gw>]])"
      [ "default-net" ]
  in
  Mirage_runtime.register_arg Arg.(value & opt (some string) None doc)

module Conf = struct
  module type Bool = sig
    val v : bool
  end

  module True = struct
    let v = true
  end

  module False = struct
    let v = false
  end

  type args = { memtrace_port : int option }

  module type S = sig
    val no_platform : bool
    val no_scrypt : bool
  end

  module Make (No_platform : Bool) (No_scrypt : Bool) : S = struct
    let no_platform = No_platform.v
    let no_scrypt = No_scrypt.v
  end
end
