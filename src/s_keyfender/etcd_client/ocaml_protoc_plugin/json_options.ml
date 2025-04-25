[@@@ocaml.ppx.context
  {
    tool_name = "ppx_driver";
    include_dirs = [];
    load_path = [];
    open_modules = [];
    for_package = None;
    debug = false;
    use_threads = false;
    use_vmthreads = false;
    recursive_types = false;
    principal = false;
    transparent_modules = false;
    unboxed_types = false;
    unsafe_string = false;
    cookies = [("library-name", "ocaml_protoc_plugin")]
  }]
type t = {
  enum_names: bool ;
  json_names: bool ;
  omit_default_values: bool }
let make ?(enum_names= true)  ?(json_names= true)  ?(omit_default_values=
  true)  () = { enum_names; json_names; omit_default_values }[@@ocaml.doc
                                                               "\n   Create options for json serialization.\n\n   If [enum_names] is true then enums are serialized as strings. If false the integer value is used when serializing.\n\n   If [json_name] is true then serialization will use the json field names. If false, the fields names will be used from the protofile as-is.\n\n   If [omit_default_values] is false then default scalar values will not be emitted to the json. The default is to omit default values.\n"]
let default = make ()
[@@@ocaml.text "/*"]
let to_int { enum_names; json_names; omit_default_values } =
  let b n = function | true -> n | false -> 0 in
  ((b 4 enum_names) + (b 2 json_names)) + (b 1 omit_default_values)[@@ocaml.doc
                                                                    " Perfect hash function "]
let of_int n =
  let b v n = (n land v) = v in
  { enum_names = (b 4 n); json_names = (b 2 n); omit_default_values = (b 1 n)
  }
let max_int =
  to_int { enum_names = true; json_names = true; omit_default_values = true }
;;()
;;()
;;()
;;()
;;()
;;()
;;()
;;()
[@@@ocaml.text "/*"]
