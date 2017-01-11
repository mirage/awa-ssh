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

open Sexplib.Conv
open Ssh_wire
open Rresult.R

type state =
  | Version_exchange       (* Handling client version *)
  | Key_exchange           (* Exchanging keys *)

type t = {
  state : state;
  peer_version : string;
}

let version_banner = "SSH-2.0-awa_ssh_0.1\r\n"

let make () =
  { state = Version_exchange;
    peer_version = "unknown" }

let find_some f = try Some (f ()) with Not_found -> None
let find_some_list f l = try Some (List.find f l)  with Not_found -> None

let pick_common ~server ~client =
  find_some_list (fun x -> List.mem x server) client

let supported_kex = {
  cookie = "";
  kex_algorithms = [ "diffie-hellman-group1-sha1";
                     "diffie-hellman-group14-sha1" ];
  server_host_key_algorithms = [];
  encryption_algorithms_ctos = [ "aes128-ctr" ];
  encryption_algorithms_stoc = [ "aes128-ctr" ];
  mac_algorithms_ctos = [ "hmac-sha1" ];
  mac_algorithms_stoc = [ "hmac-sha1" ];
  compression_algorithms_ctos = [ "none" ];
  compression_algorithms_stoc = [ "none" ];
  languages_ctos = [];
  languages_stoc = [];
  first_kex_packet_follows = false;
}

let make_kex_pkt cookie =
  if (String.length cookie) <> 16 then invalid_arg "Bad cookie len";
  { supported_kex with cookie }
