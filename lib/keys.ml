open Util

let src = Logs.Src.create "awa.authenticator" ~doc:"AWA authenticator"
module Log = (val Logs.src_log src : Logs.LOG)

type typ = [ `Rsa | `Ed25519 ]

let typ_of_string s =
  match String.lowercase_ascii s with
  | "rsa" -> Ok `Rsa
  | "ed25519" -> Ok `Ed25519
  | _ -> Error ("unknown key type " ^ s)

type authenticator = [
  | `No_authentication
  | `Key of Hostkey.pub
  | `Fingerprint of typ * string
]

let hostkey_matches a key =
  match a with
  | `No_authentication ->
    Log.warn (fun m -> m "NO AUTHENTICATOR");
    true
  | `Key pub' ->
    if key = pub' then begin
      Log.app (fun m -> m "host key verification successful!");
      true
    end else begin
      Log.err (fun m -> m "host key verification failed");
      false
    end
  | `Fingerprint (typ, s) ->
    let hash = Mirage_crypto.Hash.SHA256.digest (Wire.blob_of_pubkey key) in
    Log.app (fun m -> m "authenticating server fingerprint SHA256:%s"
                (Base64.encode_string ~pad:false (Cstruct.to_string hash)));
    let typ_matches = match typ, key with
      | `Ed25519, Hostkey.Ed25519_pub _ -> true
      | `Rsa, Hostkey.Rsa_pub _ -> true
      | _ -> false
    and fp_matches = Cstruct.(equal (of_string s) hash)
    in
    if typ_matches && fp_matches then begin
      Log.app (fun m -> m "host fingerprint verification successful!");
      true
    end else begin
      Log.err (fun m -> m "host fingerprint verification failed");
      false
    end

let authenticator_of_string str =
  if str = "" then
    Ok `No_authentication
  else
    match String.split_on_char ':' str with
    | [ y ; fp ] ->
      let* t =
        match y with
        | "SHA256" -> Ok `Rsa
        | y -> typ_of_string y
      in
      begin match Base64.decode ~pad:false fp with
        | Error (`Msg m) ->
          Error ("invalid authenticator (bad b64 in fingerprint): " ^ m)
        | Ok fp -> Ok (`Fingerprint (t, fp))
      end
    | _ ->
      match Base64.decode ~pad:false str with
      | Ok k ->
        let* key = Wire.pubkey_of_blob (Cstruct.of_string k) in
        Ok (`Key key)
      | Error (`Msg msg) ->
        Error (str ^ " is invalid or unsupported authenticator, b64 failed: " ^ msg)

let of_seed typ seed =
  let g =
    let seed = Cstruct.of_string seed in
    Mirage_crypto_rng.(create ~seed (module Fortuna))
  in
  match typ with
  | `Rsa ->
    let key = Mirage_crypto_pk.Rsa.generate ~g ~bits:2048 () in
    let public = Mirage_crypto_pk.Rsa.pub_of_priv key in
    let pubkey = Wire.blob_of_pubkey (Hostkey.Rsa_pub public) in
    Log.info (fun m -> m "using ssh-rsa %s"
                 (Cstruct.to_string pubkey |> Base64.encode_string));
    Hostkey.Rsa_priv key
  | `Ed25519 ->
    let priv, pub = Mirage_crypto_ec.Ed25519.generate ~g () in
    let pubkey = Wire.blob_of_pubkey (Hostkey.Ed25519_pub pub) in
    Log.info (fun m -> m "using ssh-ed25519 %s"
                 (Cstruct.to_string pubkey |> Base64.encode_string));
    Hostkey.Ed25519_priv priv

let of_string str =
  match String.split_on_char ':' str with
  | [ typ; data; ] ->
    ( match typ_of_string typ, Base64.decode data with
    | Ok `Rsa, Ok _seed -> Ok (of_seed `Rsa data)
    | Ok `Ed25519, Ok key ->
      ( match Mirage_crypto_ec.Ed25519.priv_of_cstruct (Cstruct.of_string key) with
      | Ok key -> Ok (Hostkey.Ed25519_priv key)
      | Error err -> Error (`Msg (Fmt.str "%a" Mirage_crypto_ec.pp_error err)) )
    | Error _, _ -> Error (`Msg "Invalid type of SSH key")
    | _, Error _ -> Error (`Msg "Invalid b64 key seed") )
  | _ -> Error (`Msg "Invalid SSH key format (type:b64-seed)")
