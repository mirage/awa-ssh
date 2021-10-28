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

open Awa

let ( let* ) = Result.bind

let printf = Printf.printf
let sprintf = Printf.sprintf

(* Driver callbacks  *)
let read_cstruct fd () =
  let len = Ssh.max_pkt_len in
  let buf = Bytes.create len in
  let n = Unix.read fd buf 0 len in
  if n = 0 then
    failwith "got EOF"
  else
    let cbuf = Cstruct.create n in
    Cstruct.blit_from_bytes buf 0 cbuf 0 n;
    Format.printf "read %d bytes\n%!" (Cstruct.length cbuf);
    cbuf

let write_cstruct fd buf =
  let len = Cstruct.length buf in
  let bytes = Bytes.create len in
  Cstruct.blit_to_bytes buf 0 bytes 0 len;
  let n = Unix.write fd bytes 0 len in
  assert (n > 0)

let echo t id data =
  Driver.send_channel_data t id data

let bc t id data =
  let len = Cstruct.length data in
  let line = Cstruct.sub data 0 (len - 1) |> Cstruct.to_string in
  let args = String.split_on_char ' ' line in
  let reply =
    if List.length args <> 3 then
      "Syntax error: A op B. Be nice\n"
    else
      let a = int_of_string (List.nth args 0) in
      let op = List.nth args 1 in
      let b = int_of_string (List.nth args 2) in
      match op with
      | "+" -> sprintf "%d\n" (a + b)
      | "-" -> sprintf "%d\n" (a - b)
      | "*" -> sprintf "%d\n" (a * b)
      | "/" -> if b = 0 then "Don't be an ass !\n" else sprintf "%d\n" (a / b)
      | op -> sprintf "Unknown operator %s\n" op
  in
  Driver.send_channel_data t id (Cstruct.of_string reply)

let rec serve t cmd =
  let open Server in
  let* t, poll_result = Driver.poll t in
  match poll_result with
  | Disconnected s -> Ok (printf "Disconnected: %s\n%!" s)
  | Channel_eof id -> Ok (printf "Channel %ld EOF\n%!" id)
  | Channel_data (id, data) ->
    printf "channel data %d\n%!" (Cstruct.length data);
    (match cmd with
     | None -> serve t cmd
     | Some "echo" ->
       if (Cstruct.to_string data) = "rekey\n" then
         let* t = Driver.rekey t in
         serve t cmd
       else
         let* t = echo t id data in
         serve t cmd
     | Some "bc" ->
       let* t = bc t id data in
       serve t cmd
     | _ -> Error "Unexpected cmd")
  | Channel_exec (id, exec) ->
    printf "channel exec %s\n%!" exec;
    match exec with
    | "suicide" ->
      let* _ = Driver.disconnect t in
      Ok ()
    | "ping" ->
      let* t = Driver.send_channel_data t id (Cstruct.of_string "pong\n") in
      let* _ = Driver.disconnect t in
      Ok (printf "sent pong\n%!")
    | "echo" | "bc" as c -> serve t (Some c)
    | _ ->
      let m = sprintf "Unknown command %s\n%!" exec in
      let* t = Driver.send_channel_data t id (Cstruct.of_string m) in
      printf "%s\n%!" m;
      let* t = Driver.disconnect t in
      serve t cmd

let user_db =
  (* User foo auths by passoword *)
  let foo = Auth.make_user "foo" ~password:"bar" [] in
  (* User awa auths by pubkey *)
  let fd = Unix.(openfile "test/data/awa_test_rsa.pub" [O_RDONLY] 0) in
  let file_buf = Unix_cstruct.of_fd fd in
  let key = Result.get_ok (Wire.pubkey_of_openssh file_buf) in
  Unix.close fd;
  let awa = Auth.make_user "awa" [ key ] in
  [ foo; awa ]

let rec wait_connection priv_key listen_fd server_port =
  printf "Awa server waiting connections on port %d\n%!" server_port;
  let client_fd, _ = Unix.(accept listen_fd) in
  printf "Client connected !\n%!";
  let server, msgs = Server.make priv_key user_db in
  let* t =
    Driver.of_server server msgs
      (write_cstruct client_fd)
      (read_cstruct client_fd)
      Mtime_clock.now
  in
  let () = match serve t None with
    | Ok _ -> printf "Client finished\n%!"
    | Error e -> printf "error: %s\n%!" e
  in
  Unix.close client_fd;
  wait_connection priv_key listen_fd server_port

let () =
  Mirage_crypto_rng_unix.initialize ();
  let g = Mirage_crypto_rng.(create ~seed:(Cstruct.of_string "180586") (module Fortuna)) in
  let (ec_priv,_) = Mirage_crypto_ec.Ed25519.generate ~g () in
  let priv_key = Awa.Hostkey.Ed25519_priv (ec_priv) in
  let server_port = 18022 in
  let listen_fd = Unix.(socket PF_INET SOCK_STREAM 0) in
  Unix.(setsockopt listen_fd SO_REUSEADDR true);
  Unix.(bind listen_fd (ADDR_INET (inet_addr_any, server_port)));
  Unix.listen listen_fd 1;
  match wait_connection priv_key listen_fd server_port with
  | Error e -> printf "error %s\n%!" e
  | Ok _ -> printf "ok\n%!\n"
