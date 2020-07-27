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

open Mirage_crypto_pk

type priv =
  | Rsa_priv of Rsa.priv
  | Ed25519_priv of Hacl_ed25519.priv

type pub =
  | Rsa_pub of Rsa.pub
  | Ed25519_pub of Cstruct.t

let pub_of_priv = function
  | Rsa_priv priv -> Rsa_pub (Rsa.pub_of_priv priv)
  | Ed25519_priv priv -> Ed25519_pub (Hacl_ed25519.priv_to_public priv)

let sexp_of_pub p =
  let alg = match p with Rsa_pub _ -> "RSA" | Ed25519_pub _ -> "ED25519" in
  Sexplib.Sexp.Atom ("Hostkey.sexp_of_pub " ^ alg ^ ": TODO")
let pub_of_sexp _ = failwith "Hostkey.pub_of_sexp: TODO"

let sshname = function
  | Rsa_pub _ -> "ssh-rsa"
  | Ed25519_pub _ -> "ssh-ed25519"

type alg =
  | Rsa_sha1
  | Rsa_sha256
  | Rsa_sha512
  | Ed25519

let hash = function
  | Rsa_sha1 -> `SHA1
  | Rsa_sha256 -> `SHA256
  | Rsa_sha512 -> `SHA512
  | Ed25519 -> `SHA512

let alg_of_string = function
  | "ssh-rsa" -> Ok Rsa_sha1
  | "rsa-sha2-256" -> Ok Rsa_sha256
  | "rsa-sha2-512" -> Ok Rsa_sha512
  | "ssh-ed25519" -> Ok Ed25519
  | s -> Error ("Unknown public key algorithm " ^ s)

let alg_to_string = function
  | Rsa_sha1 -> "ssh-rsa"
  | Rsa_sha256 -> "rsa-sha2-256"
  | Rsa_sha512 -> "rsa-sha2-512"
  | Ed25519 -> "ssh-ed25519"

let alg_of_sexp = function
  | Sexplib.Sexp.Atom s ->
    begin match alg_of_string s with
      | Ok alg -> alg
      | Error msg -> failwith msg
    end
  | _ -> failwith "expected sexp atom for public key algorithm"

let sexp_of_alg t = Sexplib.Sexp.Atom (alg_to_string t)

let preferred_algs = [ Ed25519 ; Rsa_sha256 ; Rsa_sha512 ; Rsa_sha1 ]

let signature_equal = Cstruct.equal

let sign alg priv blob =
  match priv with
  | Rsa_priv priv ->
    let hash = hash alg in
    Rsa.PKCS1.sign ~hash ~key:priv (`Message blob)
  | Ed25519_priv priv ->
    Hacl_ed25519.sign priv blob

let verify alg pub ~unsigned ~signed =
  match pub with
  | Rsa_pub pub ->
    let hashp h = h = hash alg in
    Rsa.PKCS1.verify ~hashp ~key:pub ~signature:signed (`Message unsigned)
  | Ed25519_pub pub ->
    Hacl_ed25519.verify ~pub ~msg:unsigned ~signature:signed
