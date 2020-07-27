
let gen_key seed typ =
  Mirage_crypto_rng_unix.initialize ();
  let b64s x = Cstruct.to_string x |> Base64.encode_string in
  let seed = match seed with
    | None -> b64s (Mirage_crypto_rng.generate 30)
    | Some x -> x
  in
  Printf.printf "seed is %s\n" seed;
  let hostkey = Awa.Keys.of_seed ~typ seed in
  let pub = Awa.Hostkey.pub_of_priv hostkey in
  let public = Awa.Wire.blob_of_pubkey pub in
  Printf.printf "%s %s awa@awa.local\n" (Awa.Hostkey.sshname pub) (b64s public);
  Ok ()

open Cmdliner

let seed =
  let doc = "Seed for private key." in
  Arg.(value & opt (some string) None & info [ "seed" ] ~doc)

let keytype =
  let doc = "private key type" in
  Arg.(value & opt (enum [ ("rsa", `RSA) ; ("ed25519", `Ed25519) ]) `RSA & info [ "keytype" ] ~doc)

let cmd =
  Term.(term_result (const gen_key $ seed $ keytype)),
  Term.info "albatross_stat_client" ~version:"%%VERSION_NUM%%"

let () = match Term.eval cmd with `Ok () -> exit 0 | _ -> exit 1
