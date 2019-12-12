open Lwt.Infix

module Make (Wm : Webmachine.S with type +'a io = 'a Lwt.t) (Hsm : Hsm.S) = struct

  module Access = Access.Make(Hsm)
  module Utils = Wm_utils.Make(Wm)(Hsm)
  module Endpoint = Endpoint.Make(Wm)(Hsm)

  class info hsm_state = object
    inherit Endpoint.base
    inherit !Endpoint.input_state_validated hsm_state [ `Operational ]
    inherit !Endpoint.role hsm_state `Administrator
    inherit Endpoint.get_json

    method private to_json =
      let json =
        Hsm.(System.system_info hsm_state |> system_info_to_yojson |> Yojson.Safe.to_string)
      in
      Wm.continue (`String json)
  end

  class reboot hsm_state = object
    inherit Endpoint.base
    inherit !Endpoint.input_state_validated hsm_state [ `Operational ]
    inherit !Endpoint.role hsm_state `Administrator
    inherit !Endpoint.post

    method! process_post rd =
      Hsm.System.reboot hsm_state ;
      Wm.continue true rd
  end

  class shutdown hsm_state = object
    inherit Endpoint.base
    inherit !Endpoint.input_state_validated hsm_state [ `Operational ]
    inherit !Endpoint.role hsm_state `Administrator
    inherit !Endpoint.post

    method! process_post rd =
      Hsm.System.shutdown hsm_state ;
      Wm.continue true rd
  end

  class reset hsm_state = object
    inherit Endpoint.base
    inherit !Endpoint.input_state_validated hsm_state [ `Operational ]
    inherit !Endpoint.role hsm_state `Administrator
    inherit !Endpoint.post

    method! process_post rd =
      Hsm.System.reset hsm_state >>= function
      | Ok () -> Wm.continue true rd
      | Error e -> Utils.respond_error e rd
  end

  class update hsm_state = object(self)
    inherit Endpoint.base
    inherit !Endpoint.input_state_validated hsm_state [ `Operational ]
    inherit !Endpoint.role hsm_state `Administrator
    inherit !Endpoint.post

    method! process_post rd =
      let body = rd.Webmachine.Rd.req_body in
      let content = Cohttp_lwt.Body.to_stream body in
      let add_content_type h = Cohttp.Header.add h "Content-Type" "application/json" in
      Hsm.System.update hsm_state content >>= function
      | Ok changes ->
        let json = Yojson.Safe.to_string (`Assoc [ "releaseNotes", `String changes ]) in
        let rd' = Webmachine.Rd.with_resp_headers add_content_type rd in
        Wm.respond ~body:(`String json) (Cohttp.Code.code_of_status `OK) rd'
      | Error e -> Utils.respond_error e rd

    method! content_types_accepted =
      Wm.continue [ ("application/octet-stream", self#process_post) ]
  end

  class commit_update hsm_state = object
    inherit Endpoint.base
    inherit !Endpoint.input_state_validated hsm_state [ `Operational ]
    inherit !Endpoint.role hsm_state `Administrator
    inherit !Endpoint.post

    method! process_post rd =
      match Hsm.System.commit_update hsm_state with
      | Error e -> Utils.respond_error e rd
      | Ok () -> Wm.continue true rd
  end

  class cancel_update hsm_state = object
    inherit Endpoint.base
    inherit !Endpoint.input_state_validated hsm_state [ `Operational ]
    inherit !Endpoint.role hsm_state `Administrator
    inherit !Endpoint.post

    method! process_post rd =
      match Hsm.System.cancel_update hsm_state with
      | Error e -> Utils.respond_error e rd
      | Ok () -> Wm.continue true rd
  end

  class backup hsm_state = object
    inherit Endpoint.base
    inherit !Endpoint.input_state_validated hsm_state [ `Operational ]
    inherit !Endpoint.role hsm_state `Administrator
    inherit !Endpoint.post

    method! process_post rd =
      let stream, push = Lwt_stream.create () in (* TODO use Lwt_stream.from *)
      Hsm.System.backup hsm_state push >>= function
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

  class restore hsm_state = object(self)
    inherit Endpoint.base
    inherit !Endpoint.input_state_validated hsm_state [ `Unprovisioned ]
    inherit !Endpoint.post

    method! process_post rd =
      let body = rd.Webmachine.Rd.req_body in
      let content = Cohttp_lwt.Body.to_stream body in
      Hsm.System.restore hsm_state rd.Webmachine.Rd.uri content >>= function
      | Error e -> Utils.respond_error e rd
      | Ok () -> Wm.continue true rd

    method! content_types_accepted =
      Wm.continue [ ("application/octet-stream", self#process_post) ]
  end
end
