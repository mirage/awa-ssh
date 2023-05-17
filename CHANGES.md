## unreleased

* FEATURE server: propagate window-change message (#55 @reynir)
* FEATURE server: implement ext-info and server-sig-algs extension (#56 @reynir)
* FEATURE server: support RFC 4419 (group key exchanges) and NIST ECDH key
  exchanges, and X25519 (#63 @hannesm)
* BUGFIX server: fix rekey (avoid allocating lots of timeout tasks (#58 @reynir)
* BUGFIX server: filter advertised host key algorithms with used host key
  (#62 @hannesm)
* awa-lwt: drop package (unused, #61 @hannesm)
* drop Driver module, embed into awa_test_server.ml (#64 @hannesm)

## v0.2.0 (2023-03-22)

* server: be able to stop using a Lwt_switch.t (#52 @dinosaure)
* server: add Pty/Set_env/Start_shell events (#53 @dinosaure)
* client: support password authentication and keyboard-interactive (#51
  @hannesm, reported by @dgjustice #31)
* client: add NIST EC curves (#31 @hannesm)
* client: try public key authenticaion only once (#50 @reynir @hannesm)
* remove (partially implemented) hostbased authentication (#31 @hannesm)
* replace deprecated Cstruct.copy by Cstruct.to_string (#53 @dinosaure)
* remove ppx_cstruct and sexplib dependencies (#54 @hannesm)

## v0.1.2 (2023-02-16)

* Adapt to mirage-crypto-rng 0.11.0 API changes (#49 @hannesm)
* Output key seeds, as expected by of_string (#48 @reynir)
* Update dune-project (formatting disabled) (#47 @tmcgilchrist)

## v0.1.1 (2022-06-14)

* awa_gen_key: output ed25519 private key instead of the seed (@hannesm, #46)

## v0.1.0 (2022-01-19)

* mirage: add server implementation, and ssh subsystem (#35, @palainp)
* client: accept channel extended data (stderr) (@art-w, #43)
* cram test for awa_gen_key and what a user provides (@dinosaure, #44)

## v0.0.5 (2021-12-14)

* use `eqaf` and hash to test the password (@dinosaure, @hannesm, #41)
* fix isomorphism between `of_seed`/`of_string` and `awa_gen_key` tool (@dinosaure, @hannesm, #40)
* provide `Keys.of_string` (@dinosaure, @hannesm, #37)
* conflict `awa` with `result < 1.5` (@hannesm, 1c3d2eb)

## v0.0.4 (2021-10-28)

* support rsa-sha2 and ed25519 in server code (#29 #30 @palainp)
* awa_test_client: add --key argument (#28 @hannesm, suggested in #27 by
  @dgjustice @palainp)
* Avoid deprecated Cstruct.len, avoid astring (@hannesm)
* Drop rresult dependency (#34 @hannesm)

## v0.0.3 (2021-04-22)

* Adapt to mirage-crypto-ec 0.10.0 API changes (#26 @hannesm)

## v0.0.2 (2021-04-14)

* Use mirage-crypto-ec instead of hack_x25519 (#24 @hannesm)
* Support X.509 >= 0.12.0 (#24 @hannesm)

## v0.0.1 (2021-01-07)

* Initial public release
