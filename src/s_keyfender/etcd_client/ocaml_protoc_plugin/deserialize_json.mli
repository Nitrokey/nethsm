val deserialize: message_name:string -> ('constr, 'a) Spec.compound_list -> 'constr -> Json.t -> 'a

(**)
val to_int64: Json.t -> int64
val to_int32: Json.t -> int32
val to_int: Json.t -> int
val to_string: Json.t -> string
val to_bytes: Json.t -> bytes
val to_float: Json.t -> float
val to_bool: Json.t -> bool
val to_list: Json.t -> Json.t list
(**)
