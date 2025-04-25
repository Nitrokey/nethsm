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
type length_delimited = {
  offset: int ;
  length: int ;
  data: string }
type field_type =
  | Varint 
  | Fixed64 
  | Fixed32 
  | Length_delimited 
type t =
  | Varint of Int64.t 
  | Varint_unboxed of int 
  | Fixed_64_bit of Int64.t 
  | Length_delimited of length_delimited 
  | Fixed_32_bit of Int32.t 
let varint v = Varint v
let varint_unboxed v = Varint_unboxed v
let fixed_32_bit v = Fixed_32_bit v
let fixed_64_bit v = Fixed_64_bit v
let length_delimited ?(offset= 0)  ?length  data =
  let length = Option.value ~default:((String.length data) - offset) length in
  Length_delimited { offset; length; data }
let string_of_field_type : field_type -> string =
  function
  | Varint -> "Varint"
  | Fixed64 -> "Fixed64"
  | Length_delimited -> "Length_delimited"
  | Fixed32 -> "Fixed32"
let pp : Format.formatter -> t -> unit =
  fun fmt ->
    function
    | Varint_unboxed a0 ->
        (Format.fprintf fmt "(@[<2>Field.Varint_unboxed@ ";
         (Format.fprintf fmt "%d") a0;
         Format.fprintf fmt "@])")
    | Varint a0 ->
        (Format.fprintf fmt "(@[<2>Field.Varint@ ";
         (Format.fprintf fmt "%LdL") a0;
         Format.fprintf fmt "@])")
    | Fixed_64_bit a0 ->
        (Format.fprintf fmt "(@[<2>Field.Fixed_64_bit@ ";
         (Format.fprintf fmt "%LdL") a0;
         Format.fprintf fmt "@])")
    | Length_delimited { offset = aoffset; length = alength; data = adata }
        ->
        (Format.fprintf fmt "@[<2>Field.Length_delimited {@,";
         (((Format.fprintf fmt "@[%s =@ " "offset";
            (Format.fprintf fmt "%d") aoffset;
            Format.fprintf fmt "@]");
           Format.fprintf fmt ";@ ";
           Format.fprintf fmt "@[%s =@ " "length";
           (Format.fprintf fmt "%d") alength;
           Format.fprintf fmt "@]");
          Format.fprintf fmt ";@ ";
          Format.fprintf fmt "@[%s =@ " "data";
          (match alength < 20 with
           | true ->
               (Format.fprintf fmt "%S") (String.sub adata aoffset alength)
           | false ->
               (Format.fprintf fmt "%S...") (String.sub adata aoffset 17));
          Format.fprintf fmt "@]");
         Format.fprintf fmt "@]}")
    | Fixed_32_bit a0 ->
        (Format.fprintf fmt "(@[<2>Field.Fixed_32_bit@ ";
         (Format.fprintf fmt "%ldl") a0;
         Format.fprintf fmt "@])")
let show : t -> string = Format.asprintf "%a" pp
