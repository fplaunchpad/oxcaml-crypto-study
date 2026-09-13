# OxCaml-Crypto

[Read the project manifesto](./manifesto.md)

OCaml's cryptographic ecosystem currently relies on high-performance implementations written in C, wrapped by thin OCaml bindings. [OxCaml](https://oxcaml.org/) was created to close the performance gap between OCaml and Rust. In the Rust ecosystem, by contrast, cryptographic libraries are implemented directly in Rust itself, without falling back to C. This project investigates whether the same is achievable in OxCaml: implementing cryptographic primitives natively, rather than wrapping existing C implementations.

---

## Setup

Toolchain version: `oxcaml-compiler.5.2.0minus39`

```sh
opam switch create oxcaml --repos ox=git+https://github.com/oxcaml/opam-repository.git,default --empty
eval $(opam env)
opam switch import opam-oxcaml.export.json
```

### Install dependencies

```sh
opam install . --deps-only --with-test
```

### Build & test

```sh
dune build
dune runtest
```

