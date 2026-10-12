open Test_utils

type certificate = int * int

module Cert = struct
  include X509.Certificate

  let id = fingerprint `SHA256
  let compare a b = String.compare (id a) (id b)
end

module IntMap = Map.Make (Int)

module Unique (O : Set.OrderedType) = struct
  module M = Map.Make (O)

  type t = { to_index : int M.t; of_index : O.t IntMap.t }

  let add item t =
    let index = M.cardinal t.to_index in
    let to_index = M.add item index t.to_index
    and of_index = IntMap.add index item t.of_index in
    { of_index; to_index }

  let find t index = IntMap.find index t.of_index
  let empty = { to_index = M.empty; of_index = IntMap.empty }

  let get_or_add r item =
    let old = !r in
    match M.find_opt item old.to_index with
    | Some i -> i
    | None ->
        r := add item old;
        M.find item !r.to_index
end

module Certs = Unique (Cert)

let certs = ref Certs.empty

module Pubkey = struct
  include X509.Public_key

  let compare a b = String.compare (id a) (id b)
end

module Pubkeys = Unique (Pubkey)

let pubkeys = ref Pubkeys.empty
let cert0 = (0, 0)
let cert1 = (1, 1)

type pubkey = int

let pubkey_of = snd

type t = Hsm.t

let add_cert_and_key name cert =
  let pubkey = X509.Certificate.public_key cert in
  certs := Certs.add cert !certs;
  pubkeys := Pubkeys.add pubkey !pubkeys;
  Logs.info (fun m ->
      m "%s: got public key id %s" name
        (X509.Public_key.id pubkey |> Base64.encode_exn))

let decode decoder s =
  let use () = Fmt.failwith "Decode failed for: %S" s in
  s |> decoder |> Logs.on_error_msg ~use

let get_pem t kind =
  Hsm.Config.tls_cert_pem t kind
  |> Lwt_main.run
  |> decode X509.Certificate.decode_pem

let hsm = Lazy.from_fun (operational_mock ~mbox:happy_mbox)

let init () =
  Logs.set_reporter (Logs_fmt.reporter ());
  Logs.set_level (Some Logs.Info);
  certs := Certs.empty;
  pubkeys := Pubkeys.empty;
  let t = copy (Lazy.force hsm) in
  add_cert_and_key "API" (get_pem t Keyfender.Config_store.API);
  add_cert_and_key "Cluster" (get_pem t Keyfender.Config_store.Cluster);
  t

let lookup_certificate cert =
  let pubkey = X509.Certificate.public_key cert in
  let i1, i2 =
    (Certs.get_or_add certs cert, Pubkeys.get_or_add pubkeys pubkey)
  in
  Logs.info (fun m ->
      m "got public key id %s: %d, %d"
        (X509.Public_key.id pubkey |> Base64.encode_exn)
        i1 i2);
  (i1, i2)

let keygen_req = {| { "type": "Curve25519", "length": 128 } |}

let api_generate hsm_state =
  Logs.info (fun m -> m "in %s" __FUNCTION__);
  admin_post_request ~hsm_state ~body:(`String keygen_req)
    "/config/tls/generate"
  |> returns_empty ~with_status:`No_content;
  add_cert_and_key "API" (get_pem hsm_state Keyfender.Config_store.API)

let cluster_generate hsm_state =
  Logs.info (fun m -> m "in %s" __FUNCTION__);
  admin_post_request ~hsm_state ~body:(`String keygen_req)
    "/cluster/tls/generate"
  |> returns_empty ~with_status:`No_content;
  add_cert_and_key "Cluster" (get_pem hsm_state Keyfender.Config_store.Cluster)

let cert_get path hsm_state =
  request ~hsm_state ~meth:`GET ~headers:admin_headers path
  |> returns_string ~with_status:`OK
  |> decode X509.Certificate.decode_pem
  |> lookup_certificate

let pubkey_get path hsm_state =
  request ~hsm_state ~meth:`GET ~headers:admin_headers path
  |> returns_string ~with_status:`OK
  |> decode X509.Public_key.decode_pem

let api_pubkey_get = cert_get "/config/tls/public.pem"
let cluster_pubkey_get = cert_get "/cluster/tls/public.pem"
let api_get = cert_get "/config/tls/cert.pem"
let cluster_get = cert_get "/cluster/tls/cert.pem"
