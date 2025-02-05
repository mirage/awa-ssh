
let gen_key seed typ =
  Mirage_crypto_rng_unix.use_default ();
  let seed = match seed with
    | None -> Base64.encode_string (Mirage_crypto_rng.generate 30)
    | Some x -> x
  in
  let hostkey = Awa.Keys.of_seed typ seed in
  (match hostkey with
   | Awa.Hostkey.Ed25519_priv k ->
     let p = Mirage_crypto_ec.Ed25519.priv_to_octets k in
     Printf.printf "private key: %s:%s\n"
       Awa.Keys.(string_of_typ `Ed25519)
       (Base64.encode_string p)
   | Rsa_priv _ ->
     Printf.printf "private key seed: %s:%s\n"
       Awa.Keys.(string_of_typ `Rsa) seed);
  let pub = Awa.Hostkey.pub_of_priv hostkey in
  let public = Awa.Wire.blob_of_pubkey pub in
  Printf.printf "%s %s awa@awa.local\n" (Awa.Hostkey.sshname pub)
    (Base64.encode_string (Cstruct.to_string public));
  Ok ()

open Cmdliner

let seed =
  let doc = "Seed for private key." in
  Arg.(value & opt (some string) None & info [ "seed" ] ~doc)

let keytype =
  let doc = "private key type" in
  Arg.(value & opt (enum [ ("rsa", `Rsa) ; ("ed25519", `Ed25519) ]) `Rsa & info [ "keytype" ] ~doc)

let cmd =
  let info = Cmd.info "awa_gen_key" ~version:"%%VERSION_NUM%%"
  and term = Term.(term_result (const gen_key $ seed $ keytype))
  in
  Cmd.v info term

let () = exit (Cmd.eval cmd)
