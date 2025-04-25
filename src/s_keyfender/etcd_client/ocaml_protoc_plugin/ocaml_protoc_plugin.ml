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
module Json = Json
module Reader = Reader
module Writer = Writer
module Service = Service
module Result = Result
module Extensions = Extensions
module Json_options = Json_options
[@@@ocaml.text "/*"]
module Serialize = Serialize
module Deserialize = Deserialize
module Serialize_json = Serialize_json
module Deserialize_json = Deserialize_json
module Spec = Spec
module Field = Field
module Merge = Merge
let apply_lazy f =
  match Sys.backend_type with
  | Native | Bytecode -> f ()
  | Other _ -> let f = Lazy.from_fun f in (fun x -> (Lazy.force f) x)
  [@@ocaml.doc
    " Apply lazy binding if the backed is neither Native or bytecode "]
  [@@inline ]
[@@@ocaml.text "/*"]
