(* Copyright 2023 - 2023, Nitrokey GmbH
   SPDX-License-Identifier: EUPL-1.2
*)

open Lwt.Infix

module Make (Wm : Webmachine.S with type +'a io = 'a Lwt.t) (Hsm : Hsm.S) =
struct
  module Endpoint = Endpoint.Make (Wm) (Hsm)

  class info hsm_state ip =
    object (self)
      inherit Endpoint.base_with_body_length
      inherit! Endpoint.input_state_validated hsm_state [ `Operational ]
      inherit! Endpoint.r_role hsm_state `Administrator ip
      inherit Endpoint.get_json

      method private to_json =
        let json =
          Hsm.System.system_info hsm_state
          |> Json.system_info_to_yojson |> Yojson.Safe.to_string
        in
        Wm.continue (`String json)

      method! generate_etag rd =
        self#to_json rd >>= function
        | Ok (`String json), _ ->
            let etag = Digest.to_hex (Digest.string json) in
            Wm.continue (Some etag) rd
        | _ -> Wm.continue None rd
    end

  class reboot hsm_state ip =
    object
      inherit Endpoint.base_with_body_length
      inherit! Endpoint.input_state_validated hsm_state [ `Operational ]
      inherit! Endpoint.r_role hsm_state `Administrator ip
      inherit! Endpoint.post
      inherit! Endpoint.no_cache

      method! process_post rd =
        Hsm.System.reboot hsm_state >>= fun () -> Wm.continue true rd
    end

  class shutdown hsm_state ip =
    object
      inherit Endpoint.base_with_body_length

      inherit!
        Endpoint.input_state_validated
          hsm_state
          [ `Operational; `Locked; `Unprovisioned ]

      inherit! Endpoint.post
      inherit! Endpoint.no_cache
      inherit! Endpoint.r_role hsm_state `Administrator ip as r_role

      method! process_post rd =
        Hsm.System.shutdown hsm_state >>= fun () -> Wm.continue true rd

      method! is_authorized rd =
        match Hsm.state hsm_state with
        | `Locked | `Unprovisioned -> Wm.continue `Authorized rd
        | `Operational -> Endpoint.Access.is_authorized hsm_state ip rd

      method! forbidden rd =
        match Hsm.state hsm_state with
        | `Locked | `Unprovisioned -> Wm.continue false rd
        | `Operational -> r_role#forbidden rd
    end

  class factory_reset hsm_state ip =
    object
      inherit Endpoint.base_with_body_length
      inherit! Endpoint.input_state_validated hsm_state [ `Operational ]
      inherit! Endpoint.r_role hsm_state `Administrator ip
      inherit! Endpoint.post
      inherit! Endpoint.no_cache

      method! process_post rd =
        Hsm.System.factory_reset hsm_state >>= fun () -> Wm.continue true rd
    end

  class update hsm_state ip =
    object (self)
      inherit Endpoint.base
      inherit! Endpoint.input_state_validated hsm_state [ `Operational ]
      inherit! Endpoint.r_role hsm_state `Administrator ip
      inherit! Endpoint.post
      inherit! Endpoint.no_cache

      method! process_post rd =
        let body = rd.Webmachine.Rd.req_body in
        let content = Cohttp_lwt.Body.to_stream body in
        Hsm.System.update hsm_state content >>= function
        | Ok changes ->
            let json =
              Yojson.Safe.to_string
                (`Assoc [ ("releaseNotes", `String changes) ])
            in
            let rd' = { rd with resp_body = `String json } in
            Wm.continue true rd'
        | Error e -> Endpoint.respond_error e rd

      method! content_types_accepted =
        Wm.continue [ ("application/octet-stream", self#process_post) ]
    end

  class commit_update hsm_state ip =
    object
      inherit Endpoint.base_with_body_length
      inherit! Endpoint.input_state_validated hsm_state [ `Operational ]
      inherit! Endpoint.r_role hsm_state `Administrator ip
      inherit! Endpoint.post
      inherit! Endpoint.no_cache

      method! process_post rd =
        Hsm.System.commit_update hsm_state >>= function
        | Error e -> Endpoint.respond_error e rd
        | Ok () -> Wm.continue true rd
    end

  class cancel_update hsm_state ip =
    object
      inherit Endpoint.base_with_body_length
      inherit! Endpoint.input_state_validated hsm_state [ `Operational ]
      inherit! Endpoint.r_role hsm_state `Administrator ip
      inherit! Endpoint.post
      inherit! Endpoint.no_cache

      method! process_post rd =
        match Hsm.System.cancel_update hsm_state with
        | Error e -> Endpoint.respond_error e rd
        | Ok () -> Wm.continue true rd
    end

  class backup hsm_state ip =
    object
      inherit Endpoint.base_with_body_length
      inherit! Endpoint.input_state_validated hsm_state [ `Operational ]
      inherit! Endpoint.r_role hsm_state `Backup ip
      inherit! Endpoint.post
      inherit! Endpoint.no_cache

      method! process_post rd =
        let stream, push = Lwt_stream.create () in
        (* TODO use Lwt_stream.from *)
        Hsm.System.backup hsm_state push >>= function
        | Error e -> Endpoint.respond_error e rd
        | Ok () ->
            let rd' = { rd with resp_body = `Stream stream } in
            Wm.continue true rd'

      method! content_types_provided =
        Wm.continue [ ("application/octet-stream", Wm.continue `Empty) ]
    end

  class restore hsm_state ip =
    object
      inherit Endpoint.base

      inherit!
        Endpoint.input_state_validated
          hsm_state
          [ `Unprovisioned; `Operational ]

      inherit! Endpoint.post
      inherit! Endpoint.no_cache
      inherit! Endpoint.r_role hsm_state `Administrator ip as r_role
      val mutable content_type = None

      method! known_content_type rd =
        match Cohttp.Header.get rd.req_headers "Content-Type" with
        | None ->
            Logs.err (fun m ->
                m
                  "There seems to be no header field Content-Type. A \
                   Content-Type must be provided.");
            Wm.continue false rd
        | Some v -> (
            (*
                Must end with "\r\n". To be on the safe side, we add it.
                See https://discuss.ocaml.org/t/multipart-form-data/8411/3
            *)
            match Multipart_form.Content_type.of_string (v ^ "\r\n") with
            | Error (`Msg err) ->
                Logs.err (fun m -> m "Parsing Content-Type failed with: %s" err);
                Wm.continue false rd
            | Ok v ->
                content_type <- Some v;
                Wm.continue true rd)

      method! process_post rd =
        let body = rd.Webmachine.Rd.req_body in
        let content = Cohttp_lwt.Body.to_stream body in

        let identify _ = "" in
        (* As web machine ensures that known_content_type is executed first, we can be sure that content_type is Some _ and not None.*)
        let `Parse th, stream =
          Multipart_form_lwt.stream ~identify content
            (content_type |> Option.get)
        in
        Lwt.dont_wait (fun () -> th >|= fun _ -> ()) (fun _ -> ());
        let handle () =
          Lwt_stream.get stream >>= function
          | None ->
              Endpoint.respond_error (Bad_request, "Body cannot be empty.") rd
          | Some (_, _, metadata) -> (
              let rec read_all s acc =
                if String.length acc > 1024 then
                  Lwt.return_error (Hsm.Bad_request, "Meta data is too large.")
                else
                  Lwt_stream.get s >>= function
                  | None -> Lwt.return_ok acc
                  | Some x -> read_all s (acc ^ x)
              in
              read_all metadata "" >>= function
              | Error e -> Endpoint.respond_error e rd
              | Ok json -> (
                  Lwt_stream.get stream >>= function
                  | None ->
                      Endpoint.respond_error
                        (Bad_request, "Backup data cannot be empty.")
                        rd
                  | Some (_, _, backup) -> (
                      Hsm.System.restore hsm_state json backup >>= fun result ->
                      match result with
                      | Error e -> Endpoint.respond_error e rd
                      | Ok () -> Wm.continue true rd)))
        in
        handle () >|= fun result ->
        Lwt.cancel th;
        result

      method! is_authorized rd =
        match Hsm.state hsm_state with
        | `Unprovisioned -> Wm.continue `Authorized rd
        | `Operational -> Endpoint.Access.is_authorized hsm_state ip rd
        | `Locked -> assert false

      method! forbidden rd =
        match Hsm.state hsm_state with
        | `Unprovisioned -> Wm.continue false rd
        | `Operational -> r_role#forbidden rd
        | `Locked -> assert false
    end
end
