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
module type Message  = Spec.Message[@@deprecated "Use Spec.Message"]
module type Rpc  =
  sig
    module Request : Spec.Message
    module Response : Spec.Message
    val name : string[@@ocaml.doc
                       " gRPC service name as defined by the gRPC http2 spec.\n      see https://github.com/grpc/grpc/blob/master/doc/PROTOCOL-HTTP2.md#appendix-a---grpc-for-protobuf\n  "]
    val package_name : string option[@@ocaml.doc
                                      " Name of the enclosed package name if any "]
    val service_name : string[@@ocaml.doc
                               " Name of the service in which this method is defined "]
    val method_name : string[@@ocaml.doc " Name of the method "]
  end
let make_client_functions (type req) (type rep)
  (((module Request)  : (module Spec.Message with type t = req)),
   ((module Response)  : (module Spec.Message with type t = rep)))
  = (Request.to_proto, Response.from_proto)
let make_service_functions (type req) (type rep)
  (((module Request)  : (module Spec.Message with type t = req)),
   ((module Response)  : (module Spec.Message with type t = rep)))
  = (Request.from_proto, Response.to_proto)
