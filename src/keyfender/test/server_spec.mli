(* Copyright 2026, Nitrokey GmbH
   SPDX-License-Identifier: EUPL-1.2
*)

(* We model a certificate as an index of the [n]the unique int * int and [m]th unique key we've seen *)

val cert0 : int * int
(*@ pure *)

val cert1 : int * int
(*@ pure *)

val pubkey_of : int * int -> int
(*@ pubkey = pubkey_of cert
    pure
    ensures pubkey = snd cert
 *)

(** We cannot observe the private key of TLS int * ints, however a unique
    private key implies a unique public key, which we can observe. We model the
    uniqueness of TLS keys by a set of all public TLS keys generated during the
    lifetime of the test. *)

type t
(*@
    mutable model keys: int
    mutable model certs: int
    mutable model api_cert: int * int
    mutable model cluster_cert: int * int
*)

val api_get : t -> int * int
(*@ cert, pubkey = api_get t
    pure
    ensures (cert, pubkey) = t.api_cert
*)

val cluster_get : t -> int * int
(*@ cert, pubkey = cluster_get t
    pure
    ensures (cert, pubkey) = t.cluster_cert
*)

val init : unit -> t
(*@ t = init ()
    ensures t.keys = 2
    ensures t.certs = 2
    ensures t.api_cert = cert0
    ensures t.cluster_cert = cert1
*)

val api_generate : t -> unit
(*@ api_generate t
    modifies t.keys
    modifies t.certs
    modifies t.api_cert
    ensures t.keys = old t.keys + 1
    ensures t.certs = old t.certs + 1
    ensures t.api_cert = (old t.certs, old t.keys)
*)

val cluster_generate : t -> unit
(*@ cluster_generate t
    modifies t.keys
    modifies t.certs
    modifies t.cluster_cert
    ensures t.keys = old t.keys + 1
    ensures t.certs = old t.certs + 1
    ensures t.cluster_cert = (old t.certs, old t.keys)
*)
