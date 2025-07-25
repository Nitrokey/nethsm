(* Copyright 2023 - 2023, Nitrokey GmbH
   SPDX-License-Identifier: EUPL-1.2
*)

(** RW is a copy of the old Mirage_kv.RW interface. The changes don't seem to
    make sense for us and anyway it's doubtful if we should keep the `Dictionary
    type, since it doesn't fit to etcd's keys. *)
module type RW = sig
  type nonrec error = private [> Mirage_kv.error ]

  val pp_error : error Fmt.t

  type t

  val disconnect : t -> unit Lwt.t

  type key = Mirage_kv.key

  val exists : t -> key -> ([ `Dictionary | `Value ] option, error) result Lwt.t
  val get : t -> key -> (string, error) result Lwt.t

  val list :
    t -> key -> ((key * [ `Dictionary | `Value ]) list, error) result Lwt.t

  val last_modified : t -> key -> (Ptime.t, error) result Lwt.t
  val digest : t -> key -> (string, error) result Lwt.t

  type nonrec write_error = private [> Mirage_kv.write_error ]

  val pp_write_error : write_error Fmt.t
  val set : t -> key -> string -> (unit, write_error) result Lwt.t
  val remove : t -> key -> (unit, write_error) result Lwt.t
  val batch : t -> ?retries:int -> (t -> 'a Lwt.t) -> 'a Lwt.t
end

module type Typed = sig
  include RW

  type value
  type read_error

  val pp_read_error : read_error Fmt.t
  val get : t -> key -> (value, read_error) result Lwt.t
  val set : t -> key -> value -> (unit, write_error) result Lwt.t
end

module Range = struct
  module Key = Mirage_kv.Key

  type t = { prefix : Key.t; start : string option; stop : string option }
  (*  Range of keys of the form [prefix//start, prefix//stop[ in lexicographical
      order.
      - start and stop correspond to a range for *one segment*:
        there is no way to describe a range spanning over multiple
        hierarchical levels.
      - start is inclusive, stop is exclusive
      - if None is given as start and/or stop, the interval is unbounded on the
        left and/or right (falls back to the maximum bounds [prefix/, prefix0[
      - in particular, if both are None, then [list_range kv r = list kv r.prefix]
  *)

  let start t = t.start
  let stop t = t.stop
  let prefix t = t.prefix

  let create ?prefix ?start ?stop () =
    { prefix = Option.value ~default:Key.empty prefix; start; stop }

  (* Calculate end of range for prefix. See
     https://etcd.io/docs/v3.5/learning/api/#key-ranges *)
  let range_end_of_prefix s =
    let rec inc b i =
      if i < 0 then Bytes.make 1 '\x00'
      else
        match Bytes.get b i with
        | '\xff' -> (inc [@tailcall]) b (i - 1)
        | c ->
            Bytes.set b i Char.(chr (code c + 1));
            Bytes.sub b 0 (i + 1)
    in
    let p = Bytes.copy s in
    inc p (Bytes.length p - 1)

  (** prepend prefix to start and stop of range *)
  let prepend t pre =
    let prefix = Key.append pre t.prefix in
    { t with prefix }

  let within t k =
    let n = Key.basename k in
    (match t.start with
    | None -> true
    | Some start -> String.compare start n <= 0)
    && match t.stop with None -> true | Some stop -> String.compare n stop < 0

  let first_key t = Option.map (fun start -> Key.(t.prefix / start)) t.start
  let range_end t = Option.map (fun stop -> Key.(t.prefix / stop)) t.stop
end

module type Ranged = sig
  include RW

  val list_range :
    t -> Range.t -> ((key * [ `Value | `Dictionary ]) list, error) result Lwt.t
  (** Return all keys in range that correspond to an entry in kv *)
end

(** Inefficient, only for test purposes, when the backend does not support
    ranged search *)
module Make_ranged (KV : RW) : Ranged with type t = KV.t = struct
  include KV

  let list_range t range =
    let open Lwt_result.Infix in
    KV.list t (Range.prefix range) >|= fun items ->
    List.filter (fun (k, _) -> Range.within range k) items
end

module type Typed_ranged = sig
  include Ranged
  include Typed with type t := t and type error := error
end
