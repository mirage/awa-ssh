(*
 * Copyright (c) 2017 Christiano F. Haesbaert <haesbaert@haesbaert.org>
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

open Nocrypto
open Sexplib.Conv
open Rresult.R

type priv =
  | Rsa_priv of Rsa.priv

type pub =
  | Rsa_pub of Rsa.pub
  | Unknown

let pub_of_priv = function
  | Rsa_priv priv -> Rsa_pub (Rsa.pub_of_priv priv)

let sexp_of_pub = function
  | Rsa_pub pub -> Nocrypto.Rsa.sexp_of_pub pub
  | Unknown -> sexp_of_string "Unknown"

(*
 * id-sha1 OBJECT IDENTIFIER ::= { iso(1) identified-organization(3)
 *     oiw(14) secsig(3) algorithms(2) 26 }
 * from OpenSSH ssh-rsa.c
 *)
let rsa_sha1_oid = Util.cs_of_bytes
    [ 0x30; 0x21;                    (* type Sequence, length 0x21 (33) *)
      0x30; 0x09;                    (* type Sequence, length 0x09 *)
      0x06; 0x05;                    (* type OID, length 0x05 *)
      0x2b; 0x0e; 0x03; 0x02; 0x1a;  (* id-sha1 OID *)
      0x05; 0x00;                    (* NULL *)
      0x04; 0x14; ]                  (* Octet string, length 0x14 (20) *)

let sshname = function
  | Rsa_pub _ -> "ssh-rsa"
  | Unknown -> "unknown"

let signature_equal = Cstruct.equal

let sign priv blob =
  match priv with
  | Rsa_priv priv ->
      Rsa.PKCS1.sig_encode priv (Cstruct.append rsa_sha1_oid blob)
