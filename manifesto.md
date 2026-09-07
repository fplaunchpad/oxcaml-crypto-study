# Cryptographic Primitives in OxCaml — Project Description

## Background

OCaml's cryptographic ecosystem currently relies on high-performance implementations written in C, wrapped by thin OCaml bindings. [OxCaml](https://oxcaml.org/) was created to close the performance gap between OCaml and Rust. In the Rust ecosystem, by contrast, cryptographic libraries are implemented directly in Rust itself, without falling back to C. This project investigates whether the same is achievable in OxCaml: implementing cryptographic primitives natively, rather than wrapping existing C implementations.

## Research Question

The core question is not whether native cryptographic implementations in OxCaml are possible in principle, that is already known to be feasible, but how well they can be made to perform. The project is framed as an exploration of the gap between what OxCaml offers today and the performance ceiling it could reach, rather than as a novel algorithmic contribution.

Preliminary investigation has already surfaced a concrete example of this gap: certain [SIMD](https://en.wikipedia.org/wiki/Single_instruction,_multiple_data) instructions required for high-performance cryptographic operations are not currently exposed by OxCaml. Identifying gaps of this kind, and what would be needed to close them, is a central part of the project's output, potentially even as upstream contributions to OxCaml itself.

## Reference Point

The project takes **[libcrux](https://github.com/cryspen/libcrux)** as its model, a formally verified cryptographic library built from a Rust implementation. libcrux's verification work is treated as out of scope for now; the immediate objective is to build an OxCaml equivalent of libcrux's underlying primitives. Verification and formal proof of these implementations are considered a distinct, later-stage research question, not a goal of this initial phase.

## Goals

The explicit goal is **not** simply to produce a working cryptographic library. It is to develop a rigorous understanding of where OxCaml performs well and where it falls short for this class of workload. Implementation is a means to that end: there is no expectation of algorithmic innovation, the cryptographic algorithms themselves are well established. The work is centered on implementation and, critically, on benchmarking, since performance is the entire motivation for relying on C in the first place.

## Methodology and Rigor

Performance comparisons against C and Rust baselines are to be treated with methodological care. Results showing OxCaml underperforming are unremarkable and expected at this stage, given OxCaml's relative immaturity and smaller tooling ecosystem. Results showing OxCaml outperforming an established baseline warrant heightened scrutiny and should be validated across multiple machines and input sizes before being treated as reliable. This discipline, comparing systematically rather than accepting favorable results at face value, is itself considered a core learning objective of the project.
