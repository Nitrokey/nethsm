(*----------------------------------------------------------------------------
 *  Copyright (c) 2019-2020 António Nuno Monteiro
 *
 *  All rights reserved.
 *
 *  Redistribution and use in source and binary forms, with or without
 *  modification, are permitted provided that the following conditions are met:
 *
 *  1. Redistributions of source code must retain the above copyright notice,
 *  this list of conditions and the following disclaimer.
 *
 *  2. Redistributions in binary form must reproduce the above copyright
 *  notice, this list of conditions and the following disclaimer in the
 *  documentation and/or other materials provided with the distribution.
 *
 *  3. Neither the name of the copyright holder nor the names of its
 *  contributors may be used to endorse or promote products derived from this
 *  software without specific prior written permission.
 *
 *  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 *  AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 *  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 *  ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 *  LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 *  CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 *  SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 *  INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 *  CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 *  ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 *  POSSIBILITY OF SUCH DAMAGE.
 *---------------------------------------------------------------------------*)

open Lwt.Infix

module Buffered_flow = struct
  type 'a t = { flow : 'a; mutable buf : Cstruct.t }

  let create flow = { flow; buf = Cstruct.empty }
end

module Make_IO (Flow : Mirage_flow.S) :
  Gluten_lwt.IO
    with type socket = Flow.flow Buffered_flow.t
     and type addr = unit = struct
  type socket = Flow.flow Buffered_flow.t
  type addr = unit

  let shutdown (sock : socket) = Flow.close sock.flow
  let shutdown_receive sock = Lwt.async (fun () -> shutdown sock)
  let shutdown_send = shutdown_receive
  let close = shutdown

  let buffered_read (sock : socket) len =
    let trunc buf =
      match Cstruct.length buf > len with
      | false -> buf
      | true ->
          let head, rest = Cstruct.split buf len in
          sock.buf <- rest;
          head
    in
    let buffered_data =
      match Cstruct.is_empty sock.buf with
      | true -> None
      | false ->
          let buf = sock.buf in
          sock.buf <- Cstruct.empty;
          Some (Ok (`Data (trunc buf)))
    in
    match buffered_data with
    | Some data -> Lwt.return data
    | None -> (
        Flow.read sock.flow >|= fun data ->
        assert (Cstruct.is_empty sock.buf);
        match data with Ok (`Data buf) -> Ok (`Data (trunc buf)) | x -> x)

  let read sock bigstring ~off ~len =
    Lwt.catch
      (fun () ->
        buffered_read sock len >|= function
        | Ok (`Data buf) ->
            Bigstringaf.blit buf.buffer ~src_off:buf.off bigstring ~dst_off:off
              ~len:buf.len;
            `Ok buf.len
        | Ok `Eof -> `Eof
        | Error error -> failwith (Format.asprintf "%a" Flow.pp_error error))
      (fun exn -> shutdown sock >>= fun () -> Lwt.fail exn)

  let writev (sock : socket) iovecs =
    let data_len = List.fold_left (fun acc e -> acc + e.Faraday.len) 0 iovecs in
    let data = Cstruct.create_unsafe data_len in
    let copy_len =
      List.fold_left
        (fun dst_off { Faraday.buffer; off; len } ->
          Bigstringaf.blit buffer ~src_off:off data.buffer ~dst_off ~len;
          dst_off + len)
        0 iovecs
    in
    assert (data_len = copy_len);
    Lwt.catch
      (fun () ->
        Flow.write sock.flow data >|= fun x ->
        match x with
        | Ok () -> `Ok data_len
        | Error `Closed -> `Closed
        | Error other_error ->
            raise
              (Failure (Format.asprintf "%a" Flow.pp_write_error other_error)))
      (fun exn -> shutdown sock >>= fun () -> Lwt.fail exn)
end

(* module Server (Flow : Mirage_flow.S) = Gluten_lwt.Server (Make_IO (Flow)) *)
module Client (Flow : Mirage_flow.S) = Gluten_lwt.Client (Make_IO (Flow))
