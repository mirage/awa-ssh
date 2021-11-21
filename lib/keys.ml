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

let of_seed ?(bits= 2048) typ seed =
  let typ = match typ with `Rsa -> `RSA | `Ed25519 -> `ED25519 in
  match X509.Private_key.of_string ~seed_or_data:`Seed ~bits typ seed with
  | Ok (`RSA k) -> Ok (Hostkey.Rsa_priv k)
  | Ok (`ED25519 k) -> Ok (Hostkey.Ed25519_priv k)
  | Ok _ -> assert false (* XXX(dinosaure): should never occur, may be a GADT is needed here! *)
  | Error _ as err -> err

let of_string str =
  match String.split_on_char ':' str with
  | [ typ; data; ] ->
    ( match typ_of_string typ with
    | Ok `Rsa ->
      let res = X509.Private_key.of_string ~seed_or_data:`Seed `RSA data in
      Result.map (function `RSA k -> Hostkey.Rsa_priv k | _ -> assert false) res
    | Ok `Ed25519 ->
      let res = X509.Private_key.of_string ~seed_or_data:`Data `ED25519 data in
      Result.map (function `ED25519 k -> Hostkey.Ed25519_priv k | _ -> assert false) res
    | Error _ -> Error (`Msg "Invalid type of SSH key") )
  | _ -> Error (`Msg "Invalid SSH key format (type:key)")
