type t

type mode = Balanced | Speed | Space

(** Create a new writer to hold serialized data.
    The writer also controls how data is serialized and allows for different modes of operation though the [mode] parameter:
    [Balanced]:: Serializes data in a strictly compliant mode. Balance space and speed.
    [Speed]:: Applies optimization which is exploiting the protobuf wire format (but not violating it). Its believed to be safe, but may confuse other protobuf deserializers. The optimization mainly speeds up serialization of large recursive message types. Resulting protobuf serialization is slightly larger than needed, but is comparable to [Space] mode in terms of extra memory used while serialization.
    [Space]:: Limits space overhead (space waste) caused when allocated datablocks cannot be fully filled. The mode causes multiple data copies while serializing to avoid space overhead. This is the default.

    [block_size] controls the minimum size of block allocation. Setting this to zero will significantly slow down serialization but reduce space overhead. Setting a high value may cause more space overhead, esp. for recursive message structures. The default is to allocate block of size 120. This size is choosen to avoid heap allocation ([malloc]) for Ocaml 5.0.
*)
val init: ?mode:mode -> ?block_size:int -> unit -> t

(** Get the protobuf encoded contents of the writer *)
val contents : t -> string

(**/**)

(* Direct functions *)
val write_fixed32_value: int32 -> t -> unit
val write_fixed64_value: int64 -> t -> unit
val write_varint_unboxed_value: int -> t -> unit
val write_varint_value: int64 -> t -> unit
val write_length_delimited_value: data:string -> offset:int -> len:int -> t -> unit
val write_const_value: string -> t -> unit

val write_length_delimited_f: write_f:(t -> 'a -> unit) -> 'a -> t -> unit
val write_field : t -> int -> Field.t -> unit

(** Construct a writer from a field list *)
val of_list: (int * Field.t) list -> t

(** Dump contents of the writer to stdout *)
val dump : t -> unit

val unused_space : t -> int
val write_varint: Bytes.t -> offset:int -> Int64.t -> int
val write_varint_unboxed: Bytes.t -> offset:int -> int -> int
(**/**)
