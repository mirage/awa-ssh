(*
 * Copyright (c) 2019 Hannes Mehnert <hannes@mehnert.org>
 *
 * All rights reversed
 *)

let () = Printexc.record_backtrace true

open Rresult.R
open Awa

let read_cstruct fd =
  let len = Ssh.max_pkt_len in
  let buf = Bytes.create len in
  let n = Unix.read fd buf 0 len in
  if n = 0 then
    failwith "got EOF"
  else
    let cbuf = Cstruct.create n in
    Cstruct.blit_from_bytes buf 0 cbuf 0 n;
    Format.printf "read %d bytes\n%!" (Cstruct.len cbuf);
    cbuf

let write_cstruct fd buf =
  let len = Cstruct.len buf in
  let bytes = Bytes.create len in
  Cstruct.blit_to_bytes buf 0 bytes 0 len;
  let n = Unix.write fd bytes 0 len in
  assert (n > 0)

let write_msg fd t msg =
  Client.output_msg t msg >>| fun (t, buf) ->
  write_cstruct fd buf;
  t

let key () =
  let g =
    let seed = Cstruct.of_string "180586" in
    Nocrypto.Rng.(create ~seed (module Generators.Fortuna))
  in
  let key = Nocrypto.Rsa.generate ~g 2048 in
  let public = Nocrypto.Rsa.pub_of_priv key in
(*  let pem = X509.Encoding.Pem.Public_key.to_pem_cstruct1 (`RSA public) in
    Printf.printf "public key PEM\n%s\n%!" (Cstruct.to_string pem); *)
  let pubkey = Wire.blob_of_pubkey (Hostkey.Rsa_pub public) in
  Printf.printf "public key ssh-rsa %s\n%!" (Cstruct.to_string (Nocrypto.Base64.encode pubkey));
  Hostkey.Rsa_priv key

let () =
  Nocrypto_entropy_unix.initialize ();
  let fd = Unix.(socket PF_INET SOCK_STREAM 0) in
  Unix.(connect fd (ADDR_INET (inet_addr_loopback, 22)));
  let send = List.fold_left (fun t msg ->
      t >>= fun t ->
      write_msg fd t msg)
  in
  let t, out = Client.make "hannes" (key ()) () in
  let r =
    send (Ok t) out >>= fun t ->
    let rec read_react t =
      let data = read_cstruct fd in
      let now = Mtime_clock.now () in
      Client.handle_input t data now >>= fun (t, replies, events) ->
      send (Ok t) replies >>= fun t ->
      Printf.printf "%d events\n" (List.length events);
      (List.iter (fun e ->
           Format.printf "some event %a\n%!" Client.pp_event e) events);
      read_react t
    in
    read_react t
  in
  match r with
  | Ok _ -> Printf.printf "all good\n%!"
  | Error msg -> Printf.printf "failed with %s\n%!" msg
