(* Copyright 2023 - 2023, Nitrokey GmbH
   SPDX-License-Identifier: EUPL-1.2
*)

open Lwt.Infix

module Make (Wm : Webmachine.S with type +'a io = 'a Lwt.t) (Hsm : Hsm.S) =
struct
  module Endpoint = Endpoint.Make (Wm) (Hsm)

  class tls_public hsm_state ip =
    object (self)
      inherit Endpoint.base_with_body_length
      inherit! Endpoint.input_state_validated hsm_state [ `Operational ]
      inherit! Endpoint.r_role hsm_state `Administrator ip

      method private get rd =
        Hsm.Config.tls_public_pem hsm_state >>= fun pk_pem ->
        Wm.continue (`String pk_pem) rd

      method content_types_provided rd =
        Wm.continue [ ("application/x-pem-file", self#get) ] rd

      method content_types_accepted rd = Wm.continue [] rd

      method! generate_etag rd =
        Hsm.Config.tls_public_pem_digest hsm_state >>= fun digest ->
        Wm.continue digest rd
    end

  class tls_cert hsm_state ip =
    object (self)
      inherit Endpoint.base_with_body_length
      inherit! Endpoint.input_state_validated hsm_state [ `Operational ]
      inherit! Endpoint.r_role hsm_state `Administrator ip

      method private get rd =
        Hsm.Config.tls_cert_pem hsm_state >>= fun cert_pem ->
        Wm.continue (`String cert_pem) rd

      method private set rd =
        let body = rd.Webmachine.Rd.req_body in
        Cohttp_lwt.Body.to_string body >>= fun content ->
        Hsm.Config.set_tls_cert_pem hsm_state content >>= function
        | Ok () ->
            let cc hdr =
              Cohttp.Header.replace hdr "Location" (Uri.path rd.uri)
            in
            let rd' = Webmachine.Rd.with_resp_headers cc rd in
            Wm.continue true rd'
        | Error e -> Endpoint.respond_error e rd

      method content_types_provided =
        Wm.continue [ ("application/x-pem-file", self#get) ]

      method content_types_accepted =
        Wm.continue [ ("application/x-pem-file", self#set) ]

      method! allowed_methods = Wm.continue [ `GET; `PUT ]

      method! generate_etag rd =
        Hsm.Config.tls_cert_digest hsm_state >>= fun digest ->
        Wm.continue digest rd
    end

  class tls_csr hsm_state ip =
    object
      inherit Endpoint.base_with_body_length
      inherit! Endpoint.input_state_validated hsm_state [ `Operational ]
      inherit! Endpoint.r_role hsm_state `Administrator ip
      inherit! Endpoint.post_json
      inherit! Endpoint.no_cache

      method private of_json json rd =
        let ok subject =
          Hsm.Config.tls_csr_pem hsm_state subject >>= function
          | Ok csr_pem ->
              let rd' = { rd with resp_body = `String csr_pem } in
              Wm.continue true rd'
          | Error e -> Endpoint.respond_error e rd
        in
        Json.to_ocaml Json.subject_req_of_yojson json
        |> Endpoint.err_to_bad_request ok rd

      method! content_types_provided =
        Wm.continue [ ("application/x-pem-file", Wm.continue `Empty) ]
    end

  class tls_generate hsm_state ip =
    object
      inherit Endpoint.base_with_body_length
      inherit! Endpoint.input_state_validated hsm_state [ `Operational ]
      inherit! Endpoint.r_role hsm_state `Administrator ip
      inherit! Endpoint.post_json
      inherit! Endpoint.no_cache

      method private of_json json rd =
        let ok (key : Json.tls_generate_key_req) =
          let open Lwt.Infix in
          (match key.typ with
          | Json.Generic -> Error "Generic"
          | RSA -> Ok `RSA
          | Curve25519 -> Ok `ED25519
          | EC_P224 -> Error "P224"
          | EC_P256 -> Ok `P256
          | EC_P384 -> Ok `P384
          | EC_P521 -> Ok `P521)
          |> function
          | Error typ ->
              Endpoint.respond_error
                (Bad_request, Fmt.str "Unsupported key type '%s' for TLS" typ)
                rd
          | Ok typ -> (
              Hsm.Config.tls_generate hsm_state typ ~length:key.length
              >>= function
              | Ok () -> Wm.continue true rd
              | Error e -> Endpoint.respond_error e rd)
        in
        Json.to_ocaml Json.tls_generate_key_req_of_yojson json
        |> Endpoint.err_to_bad_request ok rd
    end

  class unlock_passphrase hsm_state ip =
    object
      inherit Endpoint.base_with_body_length
      inherit! Endpoint.input_state_validated hsm_state [ `Operational ]
      inherit! Endpoint.r_role hsm_state `Administrator ip
      inherit! Endpoint.put_json
      inherit! Endpoint.no_cache

      method private of_json json rd =
        let ok (new_passphrase, current_passphrase) =
          Hsm.Config.change_unlock_passphrase hsm_state ~new_passphrase
            ~current_passphrase
          >>= function
          | Ok () -> Wm.continue true rd
          | Error e -> Endpoint.respond_error e rd
        in
        Json.decode_passphrase_change json |> Endpoint.err_to_bad_request ok rd
    end

  class unattended_boot hsm_state ip =
    object (self)
      inherit Endpoint.base_with_body_length
      inherit! Endpoint.input_state_validated hsm_state [ `Operational ]
      inherit! Endpoint.r_role hsm_state `Administrator ip

      method private get rd =
        Hsm.Config.unattended_boot hsm_state >>= function
        | Ok is_unattended_boot ->
            let json = Json.is_unattended_boot_to_yojson is_unattended_boot in
            Wm.continue (`String (Yojson.Safe.to_string json)) rd
        | Error e -> Endpoint.respond_error e rd

      method private set rd =
        let body = rd.Webmachine.Rd.req_body in
        Cohttp_lwt.Body.to_string body >>= fun content ->
        match Json.is_unattended_boot_of_yojson content with
        | Error e -> Endpoint.respond_error (Bad_request, e) rd
        | Ok unattended_boot -> (
            Hsm.Config.set_unattended_boot hsm_state unattended_boot
            >>= function
            | Ok () -> Wm.continue true rd
            | Error e -> Endpoint.respond_error e rd)

      method! allowed_methods = Wm.continue [ `GET; `PUT ]

      method content_types_provided =
        Wm.continue [ ("application/json", self#get) ]

      method content_types_accepted =
        Wm.continue [ ("application/json", self#set) ]

      method! generate_etag rd =
        Hsm.Config.unattended_boot_digest hsm_state >>= fun digest ->
        Wm.continue digest rd
    end

  class network hsm_state ip =
    object (self)
      inherit Endpoint.base_with_body_length
      inherit! Endpoint.input_state_validated hsm_state [ `Operational ]
      inherit! Endpoint.r_role hsm_state `Administrator ip

      method private get rd =
        Hsm.Config.network hsm_state >>= fun network ->
        let json = Json.network_to_yojson network in
        Wm.continue (`String (Yojson.Safe.to_string json)) rd

      method private set rd =
        let body = rd.Webmachine.Rd.req_body in
        Cohttp_lwt.Body.to_string body >>= fun content ->
        match Json.decode_network content with
        | Error e -> Endpoint.respond_error (Bad_request, e) rd
        | Ok network -> (
            Hsm.Config.set_network hsm_state network >>= function
            | Ok () -> Wm.continue true rd
            | Error e -> Endpoint.respond_error e rd)

      method! allowed_methods = Wm.continue [ `GET; `PUT ]

      method content_types_provided =
        Wm.continue [ ("application/json", self#get) ]

      method content_types_accepted =
        Wm.continue [ ("application/json", self#set) ]

      method! generate_etag rd =
        Hsm.Config.network_digest hsm_state >>= fun digest ->
        Wm.continue digest rd
    end

  class logging hsm_state ip =
    object (self)
      inherit Endpoint.base_with_body_length
      inherit! Endpoint.input_state_validated hsm_state [ `Operational ]
      inherit! Endpoint.r_role hsm_state `Administrator ip

      method private get rd =
        Hsm.Config.log hsm_state >>= fun log_config ->
        let json = Json.log_to_yojson log_config in
        Wm.continue (`String (Yojson.Safe.to_string json)) rd

      method private set rd =
        let body = rd.Webmachine.Rd.req_body in
        Cohttp_lwt.Body.to_string body >>= fun content ->
        match Json.decode Json.log_of_yojson content with
        | Error e -> Endpoint.respond_error (Bad_request, e) rd
        | Ok log_config -> (
            Hsm.Config.set_log hsm_state log_config >>= function
            | Ok () -> Wm.continue true rd
            | Error e -> Endpoint.respond_error e rd)

      method! allowed_methods = Wm.continue [ `GET; `PUT ]

      method content_types_provided =
        Wm.continue [ ("application/json", self#get) ]

      method content_types_accepted =
        Wm.continue [ ("application/json", self#set) ]

      method! generate_etag rd =
        Hsm.Config.log_digest hsm_state >>= fun digest -> Wm.continue digest rd
    end

  class backup_passphrase hsm_state ip =
    object
      inherit Endpoint.base_with_body_length
      inherit! Endpoint.input_state_validated hsm_state [ `Operational ]
      inherit! Endpoint.r_role hsm_state `Administrator ip
      inherit! Endpoint.put_json
      inherit! Endpoint.no_cache

      method private of_json json rd =
        let ok (new_passphrase, current_passphrase) =
          Hsm.Config.change_backup_passphrase hsm_state ~new_passphrase
            ~current_passphrase
          >>= function
          | Ok () -> Wm.continue true rd
          | Error e -> Endpoint.respond_error e rd
        in
        Json.decode_passphrase_change json |> Endpoint.err_to_bad_request ok rd
    end

  class time hsm_state ip =
    object (self)
      inherit Endpoint.base_with_body_length
      inherit! Endpoint.input_state_validated hsm_state [ `Operational ]
      inherit! Endpoint.r_role hsm_state `Administrator ip
      inherit! Endpoint.no_cache

      method private get rd =
        Hsm.Config.time hsm_state >>= fun timestamp ->
        (* Ptime.to_rfc3339 would emit a timezone (-00:00) *)
        let (y, m, d), ((hh, mm, ss), _) = Ptime.to_date_time timestamp in
        let time =
          Printf.sprintf "%04d-%02d-%02dT%02d:%02d:%02dZ" y m d hh mm ss
        in
        let json = Json.time_req_to_yojson { time } in
        Wm.continue (`String (Yojson.Safe.to_string json)) rd

      method private set rd =
        let body = rd.Webmachine.Rd.req_body in
        Cohttp_lwt.Body.to_string body >>= fun content ->
        let parse json =
          let open Rresult.R.Infix in
          Json.time_req_of_yojson json >>= fun time ->
          Json.decode_time time.time
        in
        match Json.decode parse content with
        | Error e -> Endpoint.respond_error (Bad_request, e) rd
        | Ok ts -> (
            Hsm.Config.set_time hsm_state ts >>= function
            | Ok () -> Wm.continue true rd
            | Error e -> Endpoint.respond_error e rd)

      method! allowed_methods = Wm.continue [ `GET; `PUT ]

      method content_types_provided =
        Wm.continue [ ("application/json", self#get) ]

      method content_types_accepted =
        Wm.continue [ ("application/json", self#set) ]
    end
end
