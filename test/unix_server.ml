(*
 * Copyright (c) 2016 Christiano F. Haesbaert <haesbaert@haesbaert.org>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 *)

let () = Printexc.record_backtrace true

open Rresult.R
open Awa

let printf = Printf.printf
let sprintf = Printf.sprintf

let read_cstruct fd =
  let len = Ssh.max_pkt_len in
  let buf = Bytes.create len in
  let n = Unix.read fd buf 0 len in
  if n = 0 then
    failwith "got EOF"
  else
    let cbuf = Cstruct.create n in
    Cstruct.blit_from_bytes buf 0 cbuf 0 n;
    cbuf

let write_cstruct fd buf =
  let len = Cstruct.len buf in
  let bytes = Bytes.create len in
  Cstruct.blit_to_bytes buf 0 bytes 0 len;
  let n = Unix.write fd bytes 0 len in
  assert (n > 0)

let rec serve t fd =
  let open Server in
  Engine.poll t >>= fun (t, poll_result) ->
  match poll_result with
  | Engine.No_input ->
    Engine.input_buf t (read_cstruct fd) >>= fun t -> serve t fd
  | Engine.Output buf -> write_cstruct fd buf; serve t fd
  | Engine.Disconnected s -> ok (printf "Disconnected: %s\n%!" s)
  | Engine.Channel_eof c -> ok (printf "Got EOF\n%!")
  | Engine.Channel_data (id, data) ->
    (* XXX just send back, assume it is echo *)
    Engine.send_channel_data t id data >>= fun t -> serve t fd
  | Engine.Channel_exec (id, cmd) -> match cmd with
    | "suicide" -> Engine.disconnect t >>= fun t -> serve t fd
    | "ping" ->
      Engine.send_channel_data t id "pong\n" >>= fun t ->
      Engine.disconnect t >>= fun t -> printf "sent pong\n%!";
      serve t fd
    | "echo" -> serve t fd
    | unknown ->
      let m = sprintf "Unknown command %s\n%!" cmd in
      Engine.send_channel_data t id m >>= fun t -> printf "%s\n%!" m;
      Engine.disconnect t >>= fun t -> serve t fd

let user_db =
  (* User foo auths by passoword *)
  let foo = Auth.make_user "foo" ~password:"bar" [] in
  (* User awa auths by pubkey *)
  let fd = Unix.(openfile "test/awa_test_rsa.pub" [O_RDONLY] 0) in
  let file_buf = Unix_cstruct.of_fd fd in
  let key = get_ok (Wire.pubkey_of_openssh file_buf) in
  Unix.close fd;
  let awa = Auth.make_user "awa" [ key ] in
  [ foo; awa ]

let rec wait_connection rsa listen_fd server_port =
  printf "Awa server waiting connections on port %d\n%!" server_port;
  let client_fd, _ = Unix.(accept listen_fd) in
  printf "Client connected !\n%!";
  let t = Server.make rsa user_db in
  let () = match serve t client_fd with
    | Ok _ -> printf "Client finished\n%!"
    | Error e -> printf "error: %s\n%!" e
  in
  Unix.close client_fd;
  wait_connection rsa listen_fd server_port

let () =
  Nocrypto.Rng.reseed (Cstruct.of_string "180586");
  let rsa = Hostkey.Rsa_priv (Nocrypto.Rsa.generate 2048) in
  let server_port = 18022 in
  let listen_fd = Unix.(socket PF_INET SOCK_STREAM 0) in
  Unix.(setsockopt listen_fd SO_REUSEADDR true);
  Unix.(bind listen_fd (ADDR_INET (inet_addr_any, server_port)));
  Unix.listen listen_fd 1;
  wait_connection rsa listen_fd server_port
