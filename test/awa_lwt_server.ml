(*
 * Copyright (c) 2018 Christiano F. Haesbaert <haesbaert@haesbaert.org>
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

open Lwt.Infix

let user_db =
  (* User foo auths by passoword *)
  let foo = Awa.Auth.make_user "foo" ~password:"bar" [] in
  (* User awa auths by pubkey *)
  let fd = Unix.(openfile "test/awa_test_rsa.pub" [O_RDONLY] 0) in
  let file_buf = Unix_cstruct.of_fd fd in
  let key = Rresult.R.get_ok (Awa.Wire.pubkey_of_openssh file_buf) in
  Unix.close fd;
  let awa = Awa.Auth.make_user "awa" [ key ] in
  [ foo; awa ]

let exec cmd sshin sshout _ssherror =
  let rec loop ()  =
    sshin () >>= function
    | `Eof -> Lwt.return_unit
    | `Data input -> sshout input >>= fun () -> loop ()
  in
  Lwt_io.printf "Executing %s\n%!" cmd >>= fun () ->
  loop () >>= fun () ->
  Lwt_io.printf "Execution of %s finished\n%!" cmd

let rec wait_connection rsa listen_fd server_port =
  Lwt_io.printf "Awa server waiting connections on port %d\n%!" server_port
  >>= fun () ->
  Lwt_unix.(accept listen_fd) >>= fun (client_fd, _) ->
  Lwt_io.printf "Client connected !\n%!" >>= fun () ->
  let server, msgs = Awa.Server.make rsa user_db in
  Awa_lwt.spawn_server server msgs client_fd exec >>= fun _ ->
  Lwt_io.printf "Server finished !\n%!" >>= fun () ->
  Lwt_unix.close client_fd >>= fun () ->
  wait_connection rsa listen_fd server_port

let main =
  Nocrypto.Rng.reseed (Cstruct.of_string "180586");
  let rsa = Awa.Hostkey.Rsa_priv (Nocrypto.Rsa.generate 2048) in
  let server_port = 18022 in
  let listen_fd = Lwt_unix.(socket PF_INET SOCK_STREAM 0) in
  Lwt_unix.(setsockopt listen_fd SO_REUSEADDR true);
  Lwt_unix.(bind listen_fd (ADDR_INET
                              (Unix.inet_addr_any, server_port)))
  >>= fun () ->
  Lwt_unix.listen listen_fd 1;
  wait_connection rsa listen_fd server_port

let () =
  Lwt_main.run main
