type t

(** Create a reader from a string, to be used when deserializing a protobuf type *)
val create : ?offset:int -> ?length:int -> string -> t
val offset : t -> int
val reset : t -> int -> unit

(**/**)
val read_field_header: t -> Field.field_type * int
val read_field_content : Field.field_type -> t -> Field.t
val has_more : t -> bool
val to_list : t -> (int * Field.t) list
val read_length_delimited : t -> Field.length_delimited
val read_fixed32 : t -> int32
val read_fixed64 : t -> int64

val read_varint : t -> int64
val read_varint_unboxed : t -> int
val next_field_header : t -> (Field.field_type * int) option
(**/**)
