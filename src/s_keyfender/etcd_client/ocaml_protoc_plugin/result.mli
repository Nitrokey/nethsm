type error =
  [ `Premature_end_of_input
  | `Unknown_field_type of int
  | `Wrong_field_type of string * string
  | `Illegal_value of string * Field.t
  | `Unknown_enum_value of int
  | `Unknown_enum_name of string
  | `Required_field_missing of int * string ]

exception Error of error

type 'a t = ('a, error) result

(** Raise [error] as an exception of type Result.Error *)
val raise : error -> 'a

(** catch [f] catches any exception of type Result.Error raised and returns a result type *)
val catch : (unit -> 'a) -> ('a, [> error ]) result

(** Monadic map *)
val ( >>| ) : 'a t -> ('a -> 'b) -> 'b t

(** Monadoc bind *)
val ( >>= ) : 'a t -> ('a -> 'b t) -> 'b t

(** Monadic return *)
val return : 'a -> 'a t

(** Create the error state *)
val fail : error -> 'a t

(** Get the value or fail with the given message *)
val get : msg:string -> 'a t -> 'a

(** Pretty printer of the error type *)
val pp_error : Format.formatter -> error -> unit

(** Create a string representation of [error] *)
val show_error : error -> string

(** Prettyprinter *)
val pp :
  (Format.formatter -> 'a -> unit) ->
  Format.formatter -> ('a, [< error ]) result -> unit
