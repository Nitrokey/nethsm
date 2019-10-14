type t = V0

val compare : t -> t -> [ `Smaller | `Equal | `Greater ]

val to_string : t -> string

val of_string : string -> (t, [> `Msg of string ]) result

val current : t
