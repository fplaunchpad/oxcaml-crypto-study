(lang dune 3.24)
(generate_opam_files true)

(package
 (name oxcaml-crypto-study)
 (synopsis "Performance engineering of cryptographic primtives in OxCaml")
 (license "MIT")
 (authors "Anirudh Sudhir")
 (maintainers "Anirudh Sudhir")
 (homepage "https://github.com/fplaunchpad/oxcaml-crypto-study")
 (bug_reports "https://github.com/fplaunchpad/oxcaml-crypto-study/issues")
 (depends
  ocaml
  (alcotest :with-test)
  (qcheck-core :with-test)
  (qcheck-alcotest :with-test)))
