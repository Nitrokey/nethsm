open Lwt.Infix

module Make (Wm : Webmachine.S with type +'a io = 'a Lwt.t) (Hsm : Hsm.S) = struct

  let decode_network json =
    Json.decode Hsm.Config.network_of_yojson json

  let is_unattended_boot_to_yojson r =
    `Assoc [ ("status", `String (if r then "on" else "off")) ]

  let is_unattended_boot_of_yojson content =
    let parse = function
    | `Assoc [ ("status", `String r) ] ->
      if r = "on"
      then Ok true
      else if r = "off"
      then Ok false
      else Error "Invalid status data, expected 'on' or 'off'."
    | _ -> Error "Invalid status data, expected a dictionary with one entry 'status'."
    in
    Json.decode parse content

  type time_req = { time : string } [@@deriving yojson]

  module Access = Access.Make(Hsm)
  module Utils = Wm_utils.Make(Wm)(Hsm)
  module Endpoint = Endpoint.Make(Wm)(Hsm)

  class tls_public hsm_state = object(self)
    inherit Endpoint.base
    inherit !Endpoint.input_state_validated hsm_state [ `Operational ]

    method private get rd =
      Hsm.Config.tls_public_pem hsm_state >>= fun pk_pem ->
      Wm.continue (`String pk_pem) rd

    method content_types_provided rd =
      Wm.continue [ ("application/x-pem-file", self#get) ] rd

    method content_types_accepted rd =
      Wm.continue [ ] rd

    method! is_authorized rd =
      Access.is_authorized hsm_state rd >>= fun (auth, rd') ->
      Wm.continue auth rd'

    method! forbidden rd =
      Access.forbidden hsm_state `Administrator rd >>= fun auth ->
      Wm.continue auth rd
  end

  class tls_cert hsm_state = object(self)
    inherit Endpoint.base
    inherit !Endpoint.input_state_validated hsm_state [ `Operational ]

    method private get rd =
      Hsm.Config.tls_cert_pem hsm_state >>= fun cert_pem ->
      Wm.continue (`String cert_pem) rd

    method private set rd =
      let body = rd.Webmachine.Rd.req_body in
      Cohttp_lwt.Body.to_string body >>= fun content ->
      Hsm.Config.set_tls_cert_pem hsm_state content >>= function
      | Ok () -> Wm.continue true rd
      | Error e -> Utils.respond_error e rd

    method content_types_provided =
      Wm.continue [ ("application/x-pem-file", self#get) ]

    method content_types_accepted =
      Wm.continue [ ("application/x-pem-file", self#set) ]

    method !allowed_methods = Wm.continue [ `GET ; `PUT ]

    method! is_authorized rd =
      Access.is_authorized hsm_state rd >>= fun (auth, rd') ->
      Wm.continue auth rd'

    method! forbidden rd =
      Access.forbidden hsm_state `Administrator rd >>= fun auth ->
      Wm.continue auth rd
  end

  class tls_csr hsm_state = object
    inherit Endpoint.base
    inherit !Endpoint.input_state_validated hsm_state [ `Operational ]
    inherit !Endpoint.post_json

    method private of_json json rd =
      let ok subject =
        Hsm.Config.tls_csr_pem hsm_state subject >>= fun csr_pem ->
        Wm.respond 200 ~body:(`String csr_pem) rd
      in
      Json.to_ocaml Json.subject_req_of_yojson json |>
      Utils.err_to_bad_request ok rd

    method! content_types_provided =
      Wm.continue [ ("application/x-pem-file", Wm.continue `Empty) ]

    method! is_authorized rd =
      Access.is_authorized hsm_state rd >>= fun (auth, rd') ->
      Wm.continue auth rd'

    method! forbidden rd =
      Access.forbidden hsm_state `Administrator rd >>= fun auth ->
      Wm.continue auth rd
  end

  class unlock_passphrase hsm_state = object
    inherit Endpoint.base
    inherit !Endpoint.input_state_validated hsm_state [ `Operational ]
    inherit !Endpoint.post_json

    method private of_json json rd =
      let ok passphrase =
        Hsm.Config.set_unlock_passphrase hsm_state ~passphrase >>= function
        | Ok () -> Wm.continue true rd
        | Error e -> Utils.respond_error e rd
      in
      Json.decode_passphrase2 json |> Utils.err_to_bad_request ok rd

    method! is_authorized rd =
      Access.is_authorized hsm_state rd >>= fun (auth, rd') ->
      Wm.continue auth rd'

    method! forbidden rd =
      Access.forbidden hsm_state `Administrator rd >>= fun auth ->
      Wm.continue auth rd
  end

  class unattended_boot hsm_state = object(self)
    inherit Endpoint.base
    inherit !Endpoint.input_state_validated hsm_state [ `Operational ]

    method private get rd =
      Hsm.Config.unattended_boot hsm_state >>= function
      | Ok is_unattended_boot ->
        let json = is_unattended_boot_to_yojson is_unattended_boot in
        Wm.continue (`String (Yojson.Safe.to_string json)) rd
      | Error e -> Utils.respond_error e rd

    method private set rd =
      let body = rd.Webmachine.Rd.req_body in
      Cohttp_lwt.Body.to_string body >>= fun content ->
      match is_unattended_boot_of_yojson content with
      | Error e -> Utils.respond_error (Bad_request, e) rd
      | Ok unattended_boot ->
        Hsm.Config.set_unattended_boot hsm_state unattended_boot >>= function
        | Ok () -> Wm.continue true rd
        | Error e -> Utils.respond_error e rd

    method !allowed_methods = Wm.continue [ `GET ; `POST ]

    method !process_post = self#set

    method content_types_provided =
      Wm.continue [ ("application/json", self#get) ]

    method content_types_accepted =
      Wm.continue [ ("application/json", self#set) ]

    method! is_authorized rd =
      Access.is_authorized hsm_state rd >>= fun (auth, rd') ->
      Wm.continue auth rd'

    method! forbidden rd =
      Access.forbidden hsm_state `Administrator rd >>= fun auth ->
      Wm.continue auth rd
  end

  class network hsm_state = object(self)
    inherit Endpoint.base
    inherit !Endpoint.input_state_validated hsm_state [ `Operational ]

    method private get rd =
      Hsm.Config.network hsm_state >>= fun network ->
      let json = Hsm.Config.network_to_yojson network in
      Wm.continue (`String (Yojson.Safe.to_string json)) rd

    method private set rd =
      let body = rd.Webmachine.Rd.req_body in
      Cohttp_lwt.Body.to_string body >>= fun content ->
      match decode_network content with
      | Error e -> Utils.respond_error (Bad_request, e) rd
      | Ok network ->
        Hsm.Config.set_network hsm_state network >>= function
        | Ok () -> Wm.continue true rd
        | Error e -> Utils.respond_error e rd

    method !allowed_methods = Wm.continue [ `GET ; `PUT ]

    method content_types_provided =
      Wm.continue [ ("application/json", self#get) ]

    method content_types_accepted =
      Wm.continue [ ("application/json", self#set) ]

    method! is_authorized rd =
      Access.is_authorized hsm_state rd >>= fun (auth, rd') ->
      Wm.continue auth rd'

    method! forbidden rd =
      Access.forbidden hsm_state `Administrator rd >>= fun auth ->
      Wm.continue auth rd
  end

  class logging hsm_state = object(self)
    inherit Endpoint.base
    inherit !Endpoint.input_state_validated hsm_state [ `Operational ]

    method private get rd =
      Hsm.Config.log hsm_state >>= fun log_config ->
      let json = Hsm.Config.log_to_yojson log_config in
      Wm.continue (`String (Yojson.Safe.to_string json)) rd

    method private set rd =
      let body = rd.Webmachine.Rd.req_body in
      Cohttp_lwt.Body.to_string body >>= fun content ->
      match Json.decode Hsm.Config.log_of_yojson content with
      | Error e -> Utils.respond_error (Bad_request, e) rd
      | Ok log_config ->
        Hsm.Config.set_log hsm_state log_config >>= function
        | Ok () -> Wm.continue true rd
        | Error e -> Utils.respond_error e rd

    method !allowed_methods = Wm.continue [ `GET ; `PUT ]

    method content_types_provided =
      Wm.continue [ ("application/json", self#get) ]

    method content_types_accepted =
      Wm.continue [ ("application/json", self#set) ]

    method! is_authorized rd =
      Access.is_authorized hsm_state rd >>= fun (auth, rd') ->
      Wm.continue auth rd'

    method! forbidden rd =
      Access.forbidden hsm_state `Administrator rd >>= fun auth ->
      Wm.continue auth rd
  end

  class backup_passphrase hsm_state = object
    inherit Endpoint.base
    inherit !Endpoint.input_state_validated hsm_state [ `Operational ]
    inherit !Endpoint.post_json

    method private of_json json rd =
      let ok passphrase =
        Hsm.Config.set_backup_passphrase hsm_state ~passphrase >>= function
        | Ok () -> Wm.continue true rd
        | Error e -> Utils.respond_error e rd
      in
      Json.decode_passphrase2 json |> Utils.err_to_bad_request ok rd

    method! is_authorized rd =
      Access.is_authorized hsm_state rd >>= fun (auth, rd') ->
      Wm.continue auth rd'

    method! forbidden rd =
      Access.forbidden hsm_state `Administrator rd >>= fun auth ->
      Wm.continue auth rd
  end

  class time hsm_state = object(self)
    inherit Endpoint.base
    inherit !Endpoint.input_state_validated hsm_state [ `Operational ]

    method private get rd =
      Hsm.Config.time hsm_state >>= fun timestamp ->
      let time = Ptime.to_rfc3339 timestamp in
      let json = time_req_to_yojson { time } in
      Wm.continue (`String (Yojson.Safe.to_string json)) rd

    method private set rd =
      let body = rd.Webmachine.Rd.req_body in
      Cohttp_lwt.Body.to_string body >>= fun content ->
      let parse json =
        let open Rresult.R.Infix in
        time_req_of_yojson json >>= fun time ->
        Json.decode_time time.time
      in
      match Json.decode parse content with
      | Error e -> Utils.respond_error (Bad_request, e) rd
      | Ok ts ->
        Hsm.Config.set_time hsm_state ts >>= function
        | Ok () -> Wm.continue true rd
        | Error e -> Utils.respond_error e rd

    method !allowed_methods = Wm.continue [ `GET ; `PUT ]

    method content_types_provided =
      Wm.continue [ ("application/json", self#get) ]

    method content_types_accepted =
      Wm.continue [ ("application/json", self#set) ]

    method! is_authorized rd =
      Access.is_authorized hsm_state rd >>= fun (auth, rd') ->
      Wm.continue auth rd'

    method! forbidden rd =
      Access.forbidden hsm_state `Administrator rd >>= fun auth ->
      Wm.continue auth rd
  end
end
