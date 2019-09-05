module Make (Wm : Webmachine.S) = struct
  type info = { 
    vendor : string ;
    product : string ;
    version : string ;
  }[@@deriving yojson]

  class handler = object(self)
    inherit [Cohttp_lwt.Body.t] Wm.resource

    method private to_json rd =
      let info = { vendor = "Nitrokey UG" ; product = "NitroHSM" ; version = "v1" } in
      let json = Yojson.Safe.to_string @@ info_to_yojson info in
      Wm.continue (`String json) rd

    method content_types_provided rd =
      Wm.continue [ ("application/json", self#to_json) ] rd

    method content_types_accepted rd =
      Wm.continue [ ] rd

  end

end
