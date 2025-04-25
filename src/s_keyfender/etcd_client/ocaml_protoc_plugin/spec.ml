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
module type T  =
  sig
    type 'a message
    type 'a enum
    type 'a oneof
    type 'a oneof_elem
    type 'a map
  end
module type Enum  =
  sig
    type t
    val name : unit -> string
    val to_int : t -> int
    val from_int : int -> t Result.t
    val from_int_exn : int -> t
    val to_string : t -> string
    val from_string_exn : string -> t
  end
module type Message  =
  sig
    type t
    type make_t
    val name : unit -> string
    val make : make_t
    val from_proto : Reader.t -> t Result.t
    val from_proto_exn : Reader.t -> t
    val to_proto : t -> Writer.t
    val to_proto' : Writer.t -> t -> unit
    val merge : t -> t -> t
    val to_json : Json_options.t -> t -> Json.t
    val from_json_exn : Json.t -> t
    val from_json : Json.t -> t Result.t
  end
module Make(T:T) =
  struct
    type packed =
      | Packed 
      | Not_packed 
    type extension_ranges = (int * int) list
    type extensions = (int * Field.t) list
    type 'a merge = 'a -> 'a -> 'a
    type field = (int * string * string)
    type scalar = [ `Scalar ]
    type message = [ `Message ]
    type (_, _) spec =
      | Double: (float, scalar) spec 
      | Float: (float, scalar) spec 
      | Int32: (Int32.t, scalar) spec 
      | UInt32: (Int32.t, scalar) spec 
      | SInt32: (Int32.t, scalar) spec 
      | Fixed32: (Int32.t, scalar) spec 
      | SFixed32: (Int32.t, scalar) spec 
      | Int32_int: (int, scalar) spec 
      | UInt32_int: (int, scalar) spec 
      | SInt32_int: (int, scalar) spec 
      | Fixed32_int: (int, scalar) spec 
      | SFixed32_int: (int, scalar) spec 
      | UInt64: (Int64.t, scalar) spec 
      | Int64: (Int64.t, scalar) spec 
      | SInt64: (Int64.t, scalar) spec 
      | Fixed64: (Int64.t, scalar) spec 
      | SFixed64: (Int64.t, scalar) spec 
      | UInt64_int: (int, scalar) spec 
      | Int64_int: (int, scalar) spec 
      | SInt64_int: (int, scalar) spec 
      | Fixed64_int: (int, scalar) spec 
      | SFixed64_int: (int, scalar) spec 
      | Bool: (bool, scalar) spec 
      | String: (string, scalar) spec 
      | Bytes: (bytes, scalar) spec 
      | Enum: (module Enum with type t = 'a) T.enum -> ('a, scalar) spec 
      | Message: (module Message with type t = 'a) T.message -> ('a, 
      message) spec 
    type _ oneof =
      | Oneof_elem: field * ('b, _) spec * (('b -> 'a) * ('a -> 'b))
      T.oneof_elem -> 'a oneof 
    type 'a basic = ('a * [ `Basic ])
    type 'a any = ('a * [ `Any ])
    type (_, _) compound =
      | Basic: field * ('a, scalar) spec * 'a -> ('a, scalar basic) compound
      
      | Basic_opt: field * ('a, 'b) spec -> ('a option, 'b basic) compound 
      | Basic_req: field * ('a, 'b) spec -> ('a, 'b any) compound 
      | Repeated: field * ('a, 'b) spec * packed -> ('a list, 'b any)
      compound 
      | Map: field * (('a, scalar) spec * ('b, 'c basic) compound) T.map ->
      (('a * 'b) list, _ any) compound 
      | Oneof: ('a oneof list * ('a -> int)) T.oneof -> ([> `not_set ] as 'a,
      _ any) compound 
    type (_, _) compound_list =
      | Nil: ('a, 'a) compound_list 
      | Nil_ext: extension_ranges -> (extensions -> 'a, 'a) compound_list 
      | Cons: ('a, _) compound * ('b, 'c) compound_list -> ('a -> 'b, 
      'c) compound_list 
    let double = Double
    let float = Float
    let int32 = Int32
    let int64 = Int64
    let uint32 = UInt32
    let uint64 = UInt64
    let sint32 = SInt32
    let sint64 = SInt64
    let fixed32 = Fixed32
    let fixed64 = Fixed64
    let sfixed32 = SFixed32
    let sfixed64 = SFixed64
    let int32_int = Int32_int
    let int64_int = Int64_int
    let uint32_int = UInt32_int
    let uint64_int = UInt64_int
    let sint32_int = SInt32_int
    let sint64_int = SInt64_int
    let fixed32_int = Fixed32_int
    let fixed64_int = Fixed64_int
    let sfixed32_int = SFixed32_int
    let sfixed64_int = SFixed64_int
    let bool = Bool
    let string = String
    let bytes = Bytes
    let enum e = Enum e
    let message m = Message m
    let some v = Some v
    let none = None
    let default_bytes v = Some (Bytes.of_string v)
    let repeated (i, s, p) = Repeated (i, s, p)
    let map (i, s) = Map (i, s)
    let basic (i, s, d) = Basic (i, s, d)
    let basic_req (i, s) = Basic_req (i, s)
    let basic_opt (i, s) = Basic_opt (i, s)
    let oneof s = Oneof s
    let oneof_elem (a, b, c) = Oneof_elem (a, b, c)
    let packed = Packed
    let not_packed = Not_packed
    let (^::) a b = Cons (a, b)
    let nil = Nil
    let nil_ext extension_ranges = Nil_ext extension_ranges
    let show : type a b. (a, b) spec -> string =
      function
      | Double -> "Double"
      | Float -> "Float"
      | Int32 -> "Int32"
      | UInt32 -> "UInt32"
      | SInt32 -> "SInt32"
      | Fixed32 -> "Fixed32"
      | SFixed32 -> "SFixed32"
      | Int32_int -> "Int32_int"
      | UInt32_int -> "UInt32_int"
      | SInt32_int -> "SInt32_int"
      | Fixed32_int -> "Fixed32_int"
      | SFixed32_int -> "SFixed32_int"
      | UInt64 -> "UInt64"
      | Int64 -> "Int64"
      | SInt64 -> "SInt64"
      | Fixed64 -> "Fixed64"
      | SFixed64 -> "SFixed64"
      | UInt64_int -> "UInt64_int"
      | Int64_int -> "Int64_int"
      | SInt64_int -> "SInt64_int"
      | Fixed64_int -> "Fixed64_int"
      | SFixed64_int -> "SFixed64_int"
      | Bool -> "Bool"
      | String -> "String"
      | Bytes -> "Bytes"
      | Enum _ -> "Enum"
      | Message _ -> "Message"
  end
include
  (Make)(struct
           type 'a message = 'a
           type 'a enum = 'a
           type 'a oneof = 'a
           type 'a oneof_elem = 'a
           type 'a map = 'a
         end)
let default_of_spec : type a. (a, scalar) spec -> a =
  function
  | Double -> 0.0
  | Float -> 0.0
  | Int32 -> Int32.zero
  | UInt32 -> Int32.zero
  | SInt32 -> Int32.zero
  | Fixed32 -> Int32.zero
  | SFixed32 -> Int32.zero
  | Int32_int -> 0
  | UInt32_int -> 0
  | SInt32_int -> 0
  | Fixed32_int -> 0
  | SFixed32_int -> 0
  | Int64 -> Int64.zero
  | UInt64 -> Int64.zero
  | SInt64 -> Int64.zero
  | Fixed64 -> Int64.zero
  | SFixed64 -> Int64.zero
  | UInt64_int -> 0
  | Int64_int -> 0
  | SInt64_int -> 0
  | Fixed64_int -> 0
  | SFixed64_int -> 0
  | Bool -> false
  | String -> ""
  | Bytes -> Bytes.create 0
  | Enum (module Enum)  -> Enum.from_int_exn 0
