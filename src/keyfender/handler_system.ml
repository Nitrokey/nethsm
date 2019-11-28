open Lwt.Infix

module Make (Wm : Webmachine.S with type +'a io = 'a Lwt.t) (Hsm : Hsm.S) = struct

  module Access = Access.Make(Hsm)
  module Utils = Wm_utils.Make(Wm)(Hsm)

  class handler hsm_state = object(self)
    inherit [Cohttp_lwt.Body.t] Wm.resource

    method private system_info rd =
      match Webmachine.Rd.lookup_path_info_exn "ep" rd with
      | "info" ->
        let open Hsm in
        let json = Yojson.Safe.to_string (system_info_to_yojson @@ System.system_info hsm_state) in
        Wm.continue (`String json) rd
      | _ -> Wm.respond (Cohttp.Code.code_of_status `Method_not_allowed) rd

    method private system rd =
      let open Hsm.System in
      match Webmachine.Rd.lookup_path_info_exn "ep" rd with
      | "reboot" ->
        reboot hsm_state ;
        Wm.continue true rd
      | "shutdown" ->
        shutdown hsm_state ;
        Wm.continue true rd
      | "reset" ->
        begin
          reset hsm_state >>= function
          | Ok () -> Wm.continue true rd
          | Error e -> Utils.respond_error e rd
        end
      | "update" ->
        begin
          let body = rd.Webmachine.Rd.req_body in
          let content = Cohttp_lwt.Body.to_stream body in
          let add_content_type h = Cohttp.Header.add h "Content-Type" "application/json" in
          update hsm_state content >>= function
          | Ok changes ->
            let json = Yojson.Safe.to_string (`Assoc [ "releaseNotes", `String changes ]) in
            let rd' = Webmachine.Rd.with_resp_headers add_content_type rd in
            Wm.respond ~body:(`String json) (Cohttp.Code.code_of_status `OK) rd'
          | Error e -> Utils.respond_error e rd
        end
      | "commit-update" ->
        begin match commit_update hsm_state with
          | Error e -> Utils.respond_error e rd
          | Ok () -> Wm.continue true rd
        end
      | "cancel-update" ->
        begin match cancel_update hsm_state with
          | Error e -> Utils.respond_error e rd
          | Ok () -> Wm.continue true rd
        end
      | "backup" ->
        let stream, push = Lwt_stream.create () in (* TODO use Lwt_stream.from *)
        begin
          backup hsm_state push >>= function
          | Error e -> Utils.respond_error e rd
          | Ok () ->
            let add_content_type h =
              Cohttp.Header.replace h "Content-Type" "application/octet-stream"
            in
            let rd' = {
              rd with resp_headers = add_content_type rd.resp_headers ;
                      resp_body = `Stream stream
            } in
            Wm.continue true rd'
        end
      | _ -> Wm.respond (Cohttp.Code.code_of_status `Method_not_allowed) rd

    (* we use this not for the service, but to check the internal state before processing requests *)
    method! service_available rd =
      if Access.is_in_state hsm_state `Operational
      then Wm.continue true rd
      else Wm.respond (Cohttp.Code.code_of_status `Precondition_failed) rd

    method! resource_exists rd =
      match Webmachine.Rd.lookup_path_info_exn "ep" rd with
      | "info"
      | "reboot"
      | "shutdown"
      | "reset"
      | "update"
      | "commit-update"
      | "cancel-update"
      | "backup"-> Wm.continue true rd
      | _ -> Wm.continue false rd

    method! is_authorized rd =
      Access.is_authorized hsm_state rd >>= fun (auth, rd') ->
      Wm.continue auth rd'

    method! forbidden rd =
      Access.forbidden hsm_state `Administrator rd >>= fun auth ->
      Wm.continue auth rd

    method !process_post rd =
      self#system rd

    method !allowed_methods rd =
      Wm.continue [ `GET ; `POST ] rd

    method content_types_provided rd =
      Wm.continue [ ("application/json", self#system_info) ] rd

    method content_types_accepted rd =
      Wm.continue [ ("application/json", self#system) ] rd

  end

  class handler_restore hsm_state = object(self)
    inherit [Cohttp_lwt.Body.t] Wm.resource

    method private get rd =
      Wm.respond (Cohttp.Code.code_of_status `Not_found) rd

    method private restore rd =
      let body = rd.Webmachine.Rd.req_body in
      let content = Cohttp_lwt.Body.to_stream body in
      Hsm.System.restore hsm_state rd.Webmachine.Rd.uri content >>= function
      | Error e -> Utils.respond_error e rd
      | Ok () -> Wm.continue true rd

    (* we use this not for the service, but to check the internal state before processing requests *)
    method! service_available rd =
      if Access.is_in_state hsm_state `Unprovisioned
      then Wm.continue true rd
      else Wm.respond (Cohttp.Code.code_of_status `Precondition_failed) rd

    method !process_post rd =
      self#restore rd

    method !allowed_methods rd =
      Wm.continue [ `POST ] rd

    method content_types_provided rd =
      Wm.continue [ ("application/octet-stream", self#get) ] rd

    method content_types_accepted rd =
      Wm.continue [ ("application/octet-stream", self#restore) ] rd

  end

end
