# dpopflow

A proof of concept of the DPoP flow described in [RFC 9449](https://datatracker.ietf.org/doc/html/rfc9449)

This project implements a client and a server that use DPoP Proof JWTs to perform a DPoP flow access grant

## Warning

This implementation is not suited for production environments.

The underlying library used [thiagocamargodacosta/dpopjwt/v0](https://github.com/thiagocamargodacosta/dpopjwt) does not implement all the requirements needed by the RFC 9449

## About

This repository contains a client that builds a DPoP Proof JWT and sends an example request to a server that returns a DPoP bound access token.
