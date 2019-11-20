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

  type time = { time : string } [@@deriving yojson]

  module Access = Access.Make(Hsm)
  module Utils = Wm_utils.Make(Wm)(Hsm)

  class handler_tls hsm_state = object(self)
    inherit [Cohttp_lwt.Body.t] Wm.resource

    method private get_pem rd =
      match Webmachine.Rd.lookup_path_info_exn "ep" rd with
      | "public.pem" ->
        Hsm.Config.tls_public_pem hsm_state >>= fun pk_pem ->
        Wm.continue (`String pk_pem) rd
      | "cert.pem" ->
        Hsm.Config.tls_cert_pem hsm_state >>= fun cert_pem ->
        Wm.continue (`String cert_pem) rd
      | _ -> Wm.respond (Cohttp.Code.code_of_status `Not_found) rd

    (* TODO maybe overwrite resource_exists instead of the above Not_found *)

    method private set_pem rd =
      let body = rd.Webmachine.Rd.req_body in
      Cohttp_lwt.Body.to_string body >>= fun content ->
      match Webmachine.Rd.lookup_path_info_exn "ep" rd with
      | "cert.pem" ->
        begin
          Hsm.Config.set_tls_cert_pem hsm_state content >>= function
          | Ok () -> Wm.continue true rd
          | Error e -> Utils.respond_error e rd
        end
      | "csr.pem" ->
        begin match Json.decode_subject content with
          | Error e -> Utils.respond_error (Bad_request, e) rd
          | Ok subject ->
            Hsm.Config.tls_csr_pem hsm_state subject >>= fun csr_pem ->
            Wm.respond 200 ~body:(`String csr_pem) rd
        end
      | _ -> Wm.respond (Cohttp.Code.code_of_status `Not_found) rd

    (* we use this not for the service, but to check the internal state before processing requests *)
    method! service_available rd =
      if Access.is_in_state hsm_state `Operational
      then Wm.continue true rd
      else Wm.respond (Cohttp.Code.code_of_status `Precondition_failed) rd

    method! is_authorized rd =
      Access.is_authorized hsm_state rd >>= fun (auth, rd') ->
      Wm.continue auth rd'

    method! forbidden rd =
      Access.forbidden hsm_state `Administrator rd >>= fun auth ->
      Wm.continue auth rd

    method !process_post rd =
      self#set_pem rd

    method !allowed_methods rd =
      Wm.continue [ `GET ; `POST ; `PUT ] rd

    method content_types_provided rd =
      Wm.continue [ ("application/x-pem-file", self#get_pem) ] rd

    method content_types_accepted rd =
      Wm.continue [ ("application/x-pem-file", self#set_pem) ;
                    ("application/json", self#set_pem) ] rd

  end

  class handler hsm_state = object(self)
    inherit [Cohttp_lwt.Body.t] Wm.resource

    method private get_json rd =
      match Webmachine.Rd.lookup_path_info_exn "ep" rd with
      | "unattended-boot" ->
        begin
          Hsm.Config.unattended_boot hsm_state >>= function
          | Ok is_unattended_boot ->
            let json = is_unattended_boot_to_yojson is_unattended_boot in
            Wm.continue (`String (Yojson.Safe.to_string json)) rd
          | Error e -> Utils.respond_error e rd
        end
      | "network" ->
        Hsm.Config.network hsm_state >>= fun network ->
        let json = Hsm.Config.network_to_yojson network in
        Wm.continue (`String (Yojson.Safe.to_string json)) rd
      | "logging" ->
        Hsm.Config.log hsm_state >>= fun log_config ->
        let json = Hsm.Config.log_to_yojson log_config in
        Wm.continue (`String (Yojson.Safe.to_string json)) rd
      | "time" ->
        Hsm.Config.time hsm_state >>= fun timestamp ->
        let time = Ptime.to_rfc3339 timestamp in
        let json = time_to_yojson { time } in
        Wm.continue (`String (Yojson.Safe.to_string json)) rd
      | _ -> Wm.respond (Cohttp.Code.code_of_status `Not_found) rd

    (* TODO maybe overwrite resource_exists instead of the above Not_found *)

    method private change_passphrase rd write json =
      match Json.decode_passphrase json with
      | Error e -> Utils.respond_error (Bad_request, e) rd
      | Ok passphrase ->
        write hsm_state ~passphrase >>= function
        | Ok () -> Wm.continue true rd
        | Error e -> Utils.respond_error e rd

    method private set_json rd =
      let body = rd.Webmachine.Rd.req_body in
      Cohttp_lwt.Body.to_string body >>= fun content ->
      match Webmachine.Rd.lookup_path_info_exn "ep" rd with
      | "unlock-passphrase" ->
        let write = Hsm.Config.set_unlock_passphrase in
        self#change_passphrase rd write content
      | "unattended-boot" ->
        begin match is_unattended_boot_of_yojson content with
          | Error e -> Utils.respond_error (Bad_request, e) rd
          | Ok unattended_boot ->
            Hsm.Config.set_unattended_boot hsm_state unattended_boot >>= function
            | Ok () -> Wm.continue true rd
            | Error e -> Utils.respond_error e rd
        end
      | "network" ->
        begin match decode_network content with
          | Error e -> Utils.respond_error (Bad_request, e) rd
          | Ok network ->
            Hsm.Config.set_network hsm_state network >>= function
            | Ok () -> Wm.continue true rd
            | Error e -> Utils.respond_error e rd
        end
      | "logging" ->
        begin match Json.decode Hsm.Config.log_of_yojson content with
          | Error e -> Utils.respond_error (Bad_request, e) rd
          | Ok log_config ->
            Hsm.Config.set_log hsm_state log_config >>= function
            | Ok () -> Wm.continue true rd
            | Error e -> Utils.respond_error e rd
        end
      | "backup-passphrase" ->
        let write = Hsm.Config.backup_passphrase in
        self#change_passphrase rd write content
      | "time" ->
        let parse json =
          let open Rresult.R.Infix in
          time_of_yojson json >>= fun time ->
          Json.decode_time time.time
        in
        begin match Json.decode parse content with
          | Error e -> Utils.respond_error (Bad_request, e) rd
          | Ok ts ->
            Hsm.Config.set_time hsm_state ts >>= function
            | Ok () -> Wm.continue true rd
            | Error e -> Utils.respond_error e rd
        end
      | _ -> Wm.respond (Cohttp.Code.code_of_status `Not_found) rd

    (* we use this not for the service, but to check the internal state before processing requests *)
    method! service_available rd =
      if Access.is_in_state hsm_state `Operational
      then Wm.continue true rd
      else Wm.respond (Cohttp.Code.code_of_status `Precondition_failed) rd

    method! is_authorized rd =
      Access.is_authorized hsm_state rd >>= fun (auth, rd') ->
      Wm.continue auth rd'

    method! forbidden rd =
      Access.forbidden hsm_state `Administrator rd >>= fun auth ->
      Wm.continue auth rd

    method !process_post rd =
      self#set_json rd

    method !allowed_methods rd =
      Wm.continue [ `GET ; `POST ; `PUT ] rd

    method content_types_provided rd =
      Wm.continue [ ("application/json", self#get_json) ] rd

    method content_types_accepted rd =
      Wm.continue [ ("application/json", self#set_json) ] rd


  end


end
