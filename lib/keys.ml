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

let of_seed ?bits typ seed =
  let typ = match typ with `Rsa -> `RSA | `Ed25519 -> `ED25519 in
  match X509.Private_key.generate ~seed:(Cstruct.of_string seed) ?bits typ with
  | `RSA k ->
    let pub = Mirage_crypto_pk.Rsa.pub_of_priv k in
    let pubkey = Wire.blob_of_pubkey (Hostkey.Rsa_pub pub) in
    Log.info (fun m -> m "using ssh-rsa %s"
                 (Cstruct.to_string pubkey |> Base64.encode_string));
    Hostkey.Rsa_priv k
  | `ED25519 k ->
    let pub = Mirage_crypto_ec.Ed25519.pub_of_priv k in
    let pubkey = Wire.blob_of_pubkey (Hostkey.Ed25519_pub pub) in
    Log.info (fun m -> m "using ssh-ed25519 %s"
                 (Cstruct.to_string pubkey |> Base64.encode_string));
    Hostkey.Ed25519_priv k
  | _ -> assert false (* XXX(dinosaure): should never occur, may be a GADT is needed here! *)

let of_string str =
  match String.split_on_char ':' str with
  | [ typ; data; ] ->
    let* typ = Result.map_error (fun m -> `Msg m) (typ_of_string typ) in
    let typ = match typ with `Rsa -> `RSA | `Ed25519 -> `ED25519 in
    let* res = X509.Private_key.of_string typ data in
    (match res with
     | `RSA k -> Ok (Hostkey.Rsa_priv k)
     | `ED25519 k -> Ok (Hostkey.Ed25519_priv k)
     | _ -> assert false)
  | _ -> Error (`Msg "Invalid SSH key format (type:key)")
