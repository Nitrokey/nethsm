val deserialize:
  ('constr, 'a) Spec.compound_list ->
  'constr -> Reader.t -> 'a

(** **)
val deserialize_full:
  ('constr, 'a) Spec.compound_list ->
  'constr -> Reader.t -> 'a

val deserialize_fast:
  ('constr, 'a) Spec.compound_list ->
  'constr -> Reader.t -> 'a
(** **)
