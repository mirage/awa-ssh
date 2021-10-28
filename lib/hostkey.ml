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
  | Ed25519_priv of Mirage_crypto_ec.Ed25519.priv

type pub =
  | Rsa_pub of Rsa.pub
  | Ed25519_pub of Mirage_crypto_ec.Ed25519.pub

let pub_of_priv = function
  | Rsa_priv priv -> Rsa_pub (Rsa.pub_of_priv priv)
  | Ed25519_priv priv -> Ed25519_pub (Mirage_crypto_ec.Ed25519.pub_of_priv priv)

let sexp_of_pub p =
  match p with
  | Rsa_pub p ->
    Sexplib.Sexp.(List [ Atom "rsa" ; Rsa.sexp_of_pub p ])
  | Ed25519_pub p ->
    let data =
      Cstruct_sexp.sexp_of_t (Mirage_crypto_ec.Ed25519.pub_to_cstruct p)
    in
    Sexplib.Sexp.(List [ Atom "ed25519" ; data ])

let pub_of_sexp _ = failwith "Hostkey.pub_of_sexp: TODO"

let sshname = function
  | Rsa_pub _ -> "ssh-rsa"
  | Ed25519_pub _ -> "ssh-ed25519"

let comptible_alg p a =
  match p with
  | Rsa_pub _ ->
    begin match a with
      | "ssh-rsa"
      | "rsa-sha2-256"
      | "rsa-sha2-512" -> true
      | _ -> false
    end
  | Ed25519_pub _ ->
    begin match a with
      | "ssh-ed25519" -> true
      | _ -> false
    end

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

let algs_of_typ = function
  | `Ed25519 -> [ Ed25519 ]
  | `Rsa -> [ Rsa_sha256 ; Rsa_sha512 ; Rsa_sha1 ]

let priv_to_typ = function
  | Rsa_priv _ -> `Rsa
  | Ed25519_priv _ -> `Ed25519

let alg_matches typ alg = List.mem alg (algs_of_typ typ)

let signature_equal = Cstruct.equal

let sign alg priv blob =
  match priv with
  | Rsa_priv priv ->
    let hash = hash alg in
    Rsa.PKCS1.sign ~hash ~key:priv (`Message blob)
  | Ed25519_priv priv ->
    Mirage_crypto_ec.Ed25519.sign ~key:priv blob

let verify alg pub ~unsigned ~signed =
  match pub with
  | Rsa_pub key ->
    let hashp h = h = hash alg in
    Rsa.PKCS1.verify ~hashp ~key ~signature:signed (`Message unsigned)
  | Ed25519_pub key ->
    Mirage_crypto_ec.Ed25519.verify ~key signed ~msg:unsigned
